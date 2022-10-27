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
package ghidra.app.plugin.core.debug.gui.register;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.mapping.ObjectBasedDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.editing.DebuggerStateEditingServicePlugin;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerRegistersProviderGuestTest extends DebuggerRegistersProviderTest {

	protected TraceGuestPlatform toy;

	@Override
	protected void createTrace() throws IOException {
		createTrace("DATA:BE:64:default");
	}

	public void createToyPlatform() throws Exception {
		try (UndoableTransaction tid = tb.startTransaction()) {
			toy = tb.trace.getPlatformManager()
					.addGuestPlatform(getToyBE64Language().getDefaultCompilerSpec());
			toy.addMappedRange(tb.addr(0), tb.addr(toy, 0), -1);
			toy.addMappedRegisterRange();
		}
	}

	@Before
	@Override
	public void setUpRegistersProviderTest() throws Exception {
		registersPlugin = addPlugin(tool, DebuggerRegistersPlugin.class);
		registersProvider = waitForComponentProvider(DebuggerRegistersProvider.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		editingService = addPlugin(tool, DebuggerStateEditingServicePlugin.class);

		createTrace();
		createToyPlatform();

		r0 = tb.reg(toy, "r0");
		pc = toy.getLanguage().getProgramCounter();
		sp = toy.getCompilerSpec().getStackPointer();
		contextreg = toy.getLanguage().getContextBaseRegister();

		pch = tb.reg(toy, "pch");
		pcl = tb.reg(toy, "pcl");

		r0h = tb.reg(toy, "r0h");
		r0l = tb.reg(toy, "r0l");

		r0Struct = new StructureDataType("r0_struct", 0);
		r0Struct.add(SignedDWordDataType.dataType, "hi", "");
		r0Struct.add(DWordDataType.dataType, "lo", "");

		baseRegs = toy.getLanguage()
				.getRegisters()
				.stream()
				.filter(Register::isBaseRegister)
				.collect(Collectors.toSet());
	}

	@Override
	protected TargetObject chooseTarget() {
		return mb.testModel.session;
	}

	@Override
	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new ObjectBasedDebuggerTargetTraceMapper(target,
			new LanguageID("DATA:BE:64:default"), new CompilerSpecID("pointer64"), Set.of()) {
			@Override
			public TraceRecorder startRecording(DebuggerModelServicePlugin service,
					Trace trace) {
				useTrace(trace);
				return super.startRecording(service, trace);
			}
		};
	}

	@Override
	protected TraceRecorder recordAndWaitSync() throws Throwable {
		TraceRecorder recorder = super.recordAndWaitSync();
		createToyPlatform();
		return recorder;
	}

	@Override
	protected TracePlatform getPlatform() {
		return toy;
	}

	@Override
	protected void activateThread(TraceThread thread) {
		traceManager.activate(traceManager.resolveThread(thread).platform(toy));
	}

	@Override
	protected void addRegisterValues(TraceThread thread, UndoableTransaction tid) {
		TraceMemorySpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
		regVals.putBytes(toy, 0, pc, tb.buf(0, 0, 0, 0, 0, 0x40, 0, 0));
		regVals.putBytes(toy, 0, sp, tb.buf(0x1f, 0, 0, 0, 0, 0, 0, 0));
		regVals.putBytes(toy, 0, r0, tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
	}

	@Override
	protected void addRegisterTypes(TraceThread thread, UndoableTransaction tid)
			throws CodeUnitInsertionException {
		TraceCodeSpace regCode =
			tb.trace.getCodeManager().getCodeRegisterSpace(thread, true);
		regCode.definedData().create(toy, Lifespan.nowOn(0), pc, PointerDataType.dataType);
		// TODO: Pointer needs to be to ram, not register space
		regCode.definedData().create(toy, Lifespan.nowOn(0), r0, r0Struct);
	}

	@Override
	public void testDefaultSelection() throws Exception {
		traceManager.openTrace(tb.trace);

		TraceThread thread = addThread();
		addRegisterValues(thread);
		traceManager.activate(traceManager.resolveThread(thread).platform(toy));
		waitForSwing();

		assertEquals(DebuggerRegistersProvider.collectCommonRegisters(toy.getCompilerSpec()),
			registersProvider.getSelectionFor(toy));
	}
}
