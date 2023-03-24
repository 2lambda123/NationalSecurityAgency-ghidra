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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.DbgModelTargetDebugContainer;
import agent.dbgeng.model.iface2.DbgModelTargetMemoryContainer;
import agent.dbgeng.model.iface2.DbgModelTargetModuleContainer;
import agent.dbgeng.model.iface2.DbgModelTargetProcess;
import agent.dbgeng.model.iface2.DbgModelTargetProcessContainer;
import agent.dbgeng.model.iface2.DbgModelTargetThreadContainer;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Process",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Debug",
			type = DbgModelTargetDebugContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Memory",
			type = DbgModelTargetMemoryContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Modules",
			type = DbgModelTargetModuleContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Threads",
			type = DbgModelTargetThreadContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME,
			type = Long.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetProcessImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(DebugProcessId debugProcessId) {
		return debugProcessId.id();
	}

	protected static String indexProcess(DbgProcess process) {
		return indexProcess(process.getId());
	}

	protected static String keyProcess(DbgProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final DbgProcess process;

	protected final DbgModelTargetDebugContainer debug;
	protected final DbgModelTargetMemoryContainer memory;
	protected final DbgModelTargetModuleContainer modules;
	protected final DbgModelTargetThreadContainer threads;

	private Integer base = 16;

	public DbgModelTargetProcessImpl(DbgModelTargetProcessContainer processes, DbgProcess process) {
		super(processes.getModel(), processes, keyProcess(process), "Process");
		this.getModel().addModelObject(process, this);
		this.getModel().addModelObject(process.getId(), this);
		this.process = process;

		this.debug = new DbgModelTargetDebugContainerImpl(this);
		this.memory = new DbgModelTargetMemoryContainerImpl(this);
		this.modules = new DbgModelTargetModuleContainerImpl(this);
		this.threads = new DbgModelTargetThreadContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			debug, //
			memory, //
			modules, //
			threads //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, DbgModelTargetThreadImpl.SUPPORTED_KINDS //
		), "Initialized");
		if (getManager().isKernelMode()) {
			TargetExecutionState state = process.getPid() > 0 ?
				TargetExecutionState.INACTIVE : TargetExecutionState.ALIVE;
			setExecutionState(state, "Initialized");
		}
		else {
			setExecutionState(TargetExecutionState.ALIVE, "Initialized");
		}

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		DebugProcessId id = process.getId();
		Long pid = process.getPid();
		if (getManager().isKernelMode()) {
			if (id.isSystem()) {
				return "["+id.id()+"]";
			}
			String pidstr = Long.toString(pid, base);
			if (base == 16) {
				pidstr = "0x" + pidstr;
			}
			Long offset = process.getOffset();
			return offset == null ? "[" + pidstr + "]" : "[" + pidstr + " : " + Long.toHexString(offset) + "]";
		}
		else {
			if (pid < 0) {
				return "[" + id.id() + "]";
			}
			String pidstr = Long.toString(pid, base);
			if (base == 16) {
				pidstr = "0x" + pidstr;
			}
			return "[" + id.id() + ":" + pidstr + "]";
		}
	}

	@Override
	public void threadStateChangedSpecific(DbgThread thread, DbgState state) {
		TargetExecutionState targetState = convertState(state);
		setExecutionState(targetState, "ThreadStateChanged");
	}

	@Override
	public CompletableFuture<Void> resume() {
		return model.gateFuture(process.cont());
	}

	@Override
	public CompletableFuture<Void> kill() {
		return model.gateFuture(process.kill());
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		getModel().assertMine(TargetObject.class, attachable);
		// NOTE: Get the object and type check it myself.
		// The typed ref could have been unsafely cast
		return model.gateFuture(process.reattach(attachable)).thenApply(set -> null);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return model.gateFuture(process.attach(pid)).thenApply(set -> null);
	}

	@Override
	public CompletableFuture<Void> detach() {
		return model.gateFuture(process.detach());
	}

	@Override
	public CompletableFuture<Void> delete() {
		return model.gateFuture(process.remove());
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			default:
				return model.gateFuture(process.step(convertToDbg(kind)));
		}
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return model.gateFuture(process.step(args));
	}

	@Override
	public void processStarted(Long pid) {
		if (pid != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, pid, //
				DISPLAY_ATTRIBUTE_NAME, getDisplay()//
			), "Started");
		}
		setExecutionState(TargetExecutionState.ALIVE, "Started");
	}

	@Override
	public void processExited(DbgProcess proc, DbgCause cause) {
		if (proc.equals(this.process)) {
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, proc.getExitCode() //
			), "Exited");
			broadcast().event(getProxy(), null, TargetEventType.PROCESS_EXITED,
				"Process " + proc.getId() + " exited code=" + proc.getExitCode(),
				List.of(getProxy()));
		}
	}

	@Override
	public void memoryChanged(DbgProcess proc, long addr, int len, DbgCause cause) {
		if (proc.equals(this.process)) {
			broadcast().invalidateCacheRequested(memory);
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		return manager.setActiveProcess(process);
	}

	@Override
	public DbgModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public DbgModelTargetModuleContainer getModules() {
		return modules;
	}

	@Override
	public DbgModelTargetMemoryContainer getMemory() {
		return memory;
	}

	@Override
	public DbgProcess getProcess() {
		return process;
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

	@Override
	public CompletableFuture<Void> resync(RefreshBehavior refreshAttributes, RefreshBehavior refreshElements) {
		if (memory != null) {
			memory.requestElements(RefreshBehavior.REFRESH_ALWAYS);
		}
		return super.resync(refreshAttributes, refreshElements);
	}

}
