/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.framework.data;

import java.util.*;

import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * <code>DomainObjectDBTransaction</code> represents an atomic undoable operation performed
 * on a single domain object.
 */
class DomainObjectDBTransaction implements TransactionInfo {

	private static int nextBaseId = 1234;

	private ArrayList<TransactionEntry> list;
	private HashMap<PluginTool, ToolState> toolStates;
	private int activeEntries = 0;
	private Status status = Status.NOT_DONE;
	private boolean hasDBTransaction = false;
	private final long id;
	private WeakSet<AbortedTransactionListener> abortedTransactionListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	// baseId used to improve differentiation between application level transaction id's
	// nextBaseId is used to prime the base and should also be incremented each time
	// a sub-transaction is added.  This approach is based upon the fact that 
	// only a single Transaction object is pending at any given time for a 
	// specific database.
	private final int baseId;

	private final DomainObject domainObject;

	DomainObjectDBTransaction(long id, DomainObject domainObject) {
		this.domainObject = domainObject;
		this.id = id;
		baseId = getNextBaseId();
		list = new ArrayList<TransactionEntry>();
		toolStates = new HashMap<PluginTool, ToolState>();
		getToolStates();
	}

	private void getToolStates() {
		if (SystemUtilities.isInHeadlessMode()) {
			return;
		}
		for (Object consumer : domainObject.getConsumerList()) {
			if (consumer instanceof PluginTool) {
				PluginTool tool = (PluginTool) consumer;
				try {
					ToolState toolState = ToolStateFactory.createToolState(tool, domainObject);
					toolStates.put(tool, toolState);
				}
				catch (Throwable t) {
					Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
				}
			}
		}
	}

	void restoreToolStates(final boolean beforeState) {
		if (toolStates.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(new Runnable() {
			@Override
			public void run() {
				// flush events blocks so that current tool state and domain object are 
				// consistent prior to restore tool state
				domainObject.flushEvents();
				if (beforeState) {
					restoreToolStatesAfterUndo(domainObject);
				}
				else {
					restoreToolStatesAfterRedo(domainObject);
				}
			}
		});
	}

	static synchronized int getNextBaseId() {
		return nextBaseId++;
	}

	/**
	 * Mark this fully committed transaction as having a corresponding 
	 * database transaction/checkpoint.
	 */
	void setHasCommittedDBTransaction() {
		if (getStatus() != Status.COMMITTED) {
			throw new IllegalStateException("transaction was not committed");
		}
		hasDBTransaction = true;
	}

	/**
	 * Returns true if this fully committed transaction has a corresponding 
	 * database transaction/checkpoint.
	 */
	@Override
	public boolean hasCommittedDBTransaction() {
		return hasDBTransaction;
	}

	@Override
	public long getID() {
		return id;
	}

	int addEntry(String description, AbortedTransactionListener listener) {
		if (listener != null) {
			abortedTransactionListeners.add(listener);
		}
		list.add(new TransactionEntry(description));
		activeEntries++;
		getNextBaseId();
		return list.size() + baseId - 1;
	}

	void endEntry(int transactionID, boolean commit) {
		TransactionEntry entry = null;
		try {
			entry = list.get(transactionID - baseId);
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalStateException("Transaction not found");
		}
		if (entry.status != Status.NOT_DONE) {
			throw new IllegalStateException(
				"Attempted to end Transaction " + "more that once: " + entry.description);
		}
		entry.status = commit ? Status.COMMITTED : Status.ABORTED;
		if (!commit) {
			status = Status.ABORTED;
		}
		if (--activeEntries == 0 && status == Status.NOT_DONE) {
			status = Status.COMMITTED;
		}
	}

	@Override
	public Status getStatus() {
		if (status == Status.ABORTED && activeEntries > 0) {
			return Status.NOT_DONE_BUT_ABORTED;
		}
		return status;
	}

	private void restoreToolStatesAfterUndo(DomainObject object) {
		List<Object> consumers = object.getConsumerList();
		for (int i = 0; i < consumers.size(); i++) {
			Object obj = consumers.get(i);
			if (obj instanceof PluginTool) {
				PluginTool tool = (PluginTool) obj;
				ToolState toolState = toolStates.get(tool);
				if (toolState != null) {
					toolState.restoreAfterUndo(object);
				}
			}
		}
	}

	private void restoreToolStatesAfterRedo(DomainObject object) {
		List<Object> consumers = object.getConsumerList();
		for (int i = 0; i < consumers.size(); i++) {
			Object obj = consumers.get(i);
			if (obj instanceof PluginTool) {
				PluginTool tool = (PluginTool) obj;
				ToolState toolState = toolStates.get(tool);
				if (toolState != null) {
					toolState.restoreAfterRedo(object);
				}
			}
		}
	}

	@Override
	public String getDescription() {
		if (list.isEmpty()) {
			return "";
		}
		for (TransactionEntry entry : list) {
			String description = entry.description;
			if (description != null && description.length() != 0) {
				return description;
			}
		}
		return "";
	}

	@Override
	public ArrayList<String> getOpenSubTransactions() {
		ArrayList<String> subTxList = new ArrayList<String>();
		Iterator<TransactionEntry> iter = list.iterator();
		while (iter.hasNext()) {
			TransactionEntry entry = iter.next();
			if (entry.status == Status.NOT_DONE) {
				subTxList.add(entry.description);
			}
		}
		return subTxList;
	}

	private static class TransactionEntry {
		String description;
		Status status;

		TransactionEntry(String description) {
			this.description = description;
			status = Status.NOT_DONE;
		}
	}

	void initAfterState(DomainObject object) {
		List<Object> consumers = object.getConsumerList();
		for (int i = 0; i < consumers.size(); i++) {
			Object obj = consumers.get(i);
			if (obj instanceof PluginTool) {
				PluginTool tool = (PluginTool) obj;
				ToolState toolState = toolStates.get(tool);
				if (toolState != null) {
					toolState.getAfterState(object);
				}
			}
		}
	}

	void abort() {
		status = Status.ABORTED;
		for (AbortedTransactionListener listener : abortedTransactionListeners) {
			listener.transactionAborted(id);
		}
		abortedTransactionListeners.clear();
	}
}
