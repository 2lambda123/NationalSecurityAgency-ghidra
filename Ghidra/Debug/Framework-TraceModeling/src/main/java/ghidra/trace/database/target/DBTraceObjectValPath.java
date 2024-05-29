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
package ghidra.trace.database.target;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.trace.model.target.*;

public class DBTraceObjectValPath implements TraceObjectValPath {
	public static final DBTraceObjectValPath EMPTY = new DBTraceObjectValPath(List.of());

	public static DBTraceObjectValPath of() {
		return EMPTY;
	}

	public static DBTraceObjectValPath of(Collection<DBTraceObjectValue> entryList) {
		return new DBTraceObjectValPath(List.copyOf(entryList));
	}

	public static DBTraceObjectValPath of(DBTraceObjectValue... entries) {
		return DBTraceObjectValPath.of(Arrays.asList(entries));
	}

	private final List<DBTraceObjectValue> entryList;
	private List<String> keyList; // lazily computed

	private DBTraceObjectValPath(List<DBTraceObjectValue> entryList) {
		this.entryList = entryList;
	}

	@Override
	public int compareTo(TraceObjectValPath o) {
		return PathComparator.KEYED.compare(getKeyList(), o.getKeyList());
	}

	@Override
	public List<DBTraceObjectValue> getEntryList() {
		return entryList;
	}

	protected List<String> computeKeyList() {
		return entryList.stream()
				.map(e -> e.getEntryKey())
				.collect(Collectors.toUnmodifiableList());
	}

	@Override
	public List<String> getKeyList() {
		if (keyList == null) {
			keyList = computeKeyList();
		}
		return keyList;
	}

	@Override
	public boolean contains(TraceObjectValue entry) {
		return entryList.contains(entry);
	}

	@Override
	public DBTraceObjectValPath prepend(TraceObjectValue entry) {
		if (!entryList.isEmpty() && entry.getTrace() != entryList.get(0).getTrace()) {
			throw new IllegalArgumentException("All values in path must be from the same trace");
		}
		if (!(entry instanceof DBTraceObjectValue val)) {
			throw new IllegalArgumentException("Value must be in the database");
		}
		DBTraceObjectValue[] arr = new DBTraceObjectValue[1 + entryList.size()];
		arr[0] = val;
		for (int i = 1; i < arr.length; i++) {
			arr[i] = entryList.get(i - 1);
		}
		return new DBTraceObjectValPath(Collections.unmodifiableList(Arrays.asList(arr)));
	}

	@Override
	public DBTraceObjectValPath append(TraceObjectValue entry) {
		if (!entryList.isEmpty() && entry.getTrace() != entryList.get(0).getTrace()) {
			throw new IllegalArgumentException("All values in path must be from the same trace");
		}
		if (!(entry instanceof DBTraceObjectValue val)) {
			throw new IllegalArgumentException("Value must be in the database");
		}
		DBTraceObjectValue[] arr = new DBTraceObjectValue[1 + entryList.size()];
		for (int i = 0; i < arr.length - 1; i++) {
			arr[i] = entryList.get(i);
		}
		arr[arr.length - 1] = val;
		return new DBTraceObjectValPath(Collections.unmodifiableList(Arrays.asList(arr)));
	}

	@Override
	public DBTraceObjectValue getFirstEntry() {
		if (entryList.isEmpty()) {
			return null;
		}
		return entryList.get(0);
	}

	@Override
	public TraceObject getSource(TraceObject ifEmpty) {
		DBTraceObjectValue first = getFirstEntry();
		return first == null ? ifEmpty : first.getParent();
	}

	@Override
	public DBTraceObjectValue getLastEntry() {
		if (entryList.isEmpty()) {
			return null;
		}
		return entryList.get(entryList.size() - 1);
	}

	@Override
	public Object getDestinationValue(Object ifEmpty) {
		DBTraceObjectValue last = getLastEntry();
		return last == null ? ifEmpty : last.getValue();
	}

	@Override
	public TraceObject getDestination(TraceObject ifEmpty) {
		DBTraceObjectValue last = getLastEntry();
		return last == null ? ifEmpty : last.getChild();
	}
}
