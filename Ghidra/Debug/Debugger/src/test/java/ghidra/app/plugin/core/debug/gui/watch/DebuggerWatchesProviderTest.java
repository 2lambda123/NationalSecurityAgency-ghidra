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
package ghidra.app.plugin.core.debug.gui.watch;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.*;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.register.*;
import ghidra.app.plugin.core.debug.service.editing.DebuggerStateEditingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerStateEditingService.StateEditingMode;
import ghidra.dbg.model.TestTargetRegisterBankInThread;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

public class DebuggerWatchesProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected static void assertNoErr(WatchRow row) {
		Throwable error = row.getError();
		if (error != null) {
			throw new AssertionError(error);
		}
	}

	protected DebuggerWatchesPlugin watchesPlugin;
	protected DebuggerWatchesProvider watchesProvider;
	protected DebuggerListingPlugin listingPlugin;
	protected DebuggerListingProvider listingProvider;
	protected DebuggerStaticMappingServicePlugin mappingService;
	protected CodeViewerProvider codeViewerProvider;
	protected DebuggerStateEditingService editingService;

	protected Register r0;
	protected Register r1;
	protected TraceThread thread;

	protected TestTargetRegisterBankInThread bank;
	protected TraceRecorder recorder;

	@Before
	public void setUpWatchesProviderTest() throws Exception {
		// Do this before listing, because DebuggerListing also implements CodeViewer
		addPlugin(tool, CodeBrowserPlugin.class);
		codeViewerProvider = waitForComponentProvider(CodeViewerProvider.class);

		watchesPlugin = addPlugin(tool, DebuggerWatchesPlugin.class);
		watchesProvider = waitForComponentProvider(DebuggerWatchesProvider.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		editingService = addPlugin(tool, DebuggerStateEditingServicePlugin.class);

		createTrace();
		r0 = tb.language.getRegister("r0");
		r1 = tb.language.getRegister("r1");
		try (UndoableTransaction tid = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread1", 0);
		}
	}

	@After
	public void tearDownWatchesProviderTest() throws Exception {
		for (WatchRow row : watchesProvider.watchTableModel.getModelData()) {
			Throwable error = row.getError();
			if (error != null) {
				Msg.info(this, "Error on watch row: ", error);
			}
		}
	}

	private void setRegisterValues(TraceThread thread) {
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryRegisterSpace regVals =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regVals.setValue(0, new RegisterValue(r0, BigInteger.valueOf(0x00400000)));
		}
	}

	@Test
	public void testAddValsAddWatchThenActivateThread() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400000", row.getRawValueString());
		assertEquals("", row.getValueString()); // NB. No data type set
		assertNoErr(row);
	}

	@Test
	public void testActivateThreadAddWatchThenAddVals() {
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");

		setRegisterValues(thread);

		waitForPass(() -> assertEquals("0x400000", row.getRawValueString()));
		assertNoErr(row);
	}

	@Test
	public void testWatchWithDataType() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0");
		row.setDataType(LongLongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400000", row.getRawValueString());
		assertEquals("400000h", row.getValueString());
		assertNoErr(row);

		assertEquals(r0.getAddress(), row.getAddress());
		assertEquals(TraceRegisterUtils.rangeForRegister(r0), row.getRange());
	}

	@Test
	public void testConstantWatch() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("0xdeadbeef:4");
		row.setDataType(LongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0xdeadbeef", row.getRawValueString());
		assertEquals("DEADBEEFh", row.getValueString());
		assertNoErr(row);

		Address constDeadbeef = tb.trace.getBaseAddressFactory().getConstantAddress(0xdeadbeefL);
		assertEquals(constDeadbeef, row.getAddress());
		assertEquals(new AddressRangeImpl(constDeadbeef, constDeadbeef), row.getRange());
	}

	@Test
	public void testUniqueWatch() {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("r0 + 8");
		row.setDataType(LongLongDataType.dataType);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		assertEquals("0x400008", row.getRawValueString());
		assertEquals("400008h", row.getValueString());
		assertNoErr(row);

		assertNull(row.getAddress());
		assertNull(row.getRange());
	}

	@Test
	public void testLiveCausesReads() throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		bank = mb.testThread1.addRegisterBank();

		// Write before we record, and verify trace has not recorded it before setting watch
		mb.testProcess1.regs.addRegistersFromLanguage(tb.language, Register::isBaseRegister);
		bank.writeRegister("r0", tb.arr(0, 0, 0, 0, 0, 0x40, 0, 0));
		mb.testProcess1.addRegion(".header", mb.rng(0, 0x1000), "r"); // Keep the listing away
		mb.testProcess1.addRegion(".text", mb.rng(0x00400000, 0x00401000), "rx");
		mb.testProcess1.memory.writeMemory(mb.addr(0x00400000), tb.arr(1, 2, 3, 4));

		recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));

		traceManager.openTrace(trace);
		traceManager.activateThread(thread);
		waitForSwing();

		// Verify no target read has occurred yet
		TraceMemoryRegisterSpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		if (regs != null) {
			assertEquals(BigInteger.ZERO, regs.getValue(0, r0).getUnsignedValue());
		}
		ByteBuffer buf = ByteBuffer.allocate(4);
		assertEquals(4, trace.getMemoryManager().getBytes(0, tb.addr(0x00400000), buf));
		assertArrayEquals(tb.arr(0, 0, 0, 0), buf.array());

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression("*:4 r0");
		row.setDataType(LongDataType.dataType);

		waitForPass(() -> {
			if (row.getError() != null) {
				ExceptionUtils.rethrow(row.getError());
			}
			assertEquals("{ 01 02 03 04 }", row.getRawValueString());
			assertEquals("1020304h", row.getValueString());
		});
		assertNoErr(row);
	}

	protected void runTestIsEditableEmu(String expression, boolean expectWritable) {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);

		assertFalse(row.isRawValueEditable());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);
		waitForSwing();

		assertNoErr(row);
		assertFalse(row.isRawValueEditable());

		performAction(watchesProvider.actionEnableEdits);
		assertEquals(expectWritable, row.isRawValueEditable());
	}

	@Test
	public void testIsRegisterEditableEmu() {
		runTestIsEditableEmu("r0", true);
	}

	@Test
	public void testIsUniqueEditableEmu() {
		runTestIsEditableEmu("r0 + 8", false);
	}

	@Test
	public void testIsMemoryEditableEmu() {
		runTestIsEditableEmu("*:8 r0", true);
	}

	protected WatchRow prepareTestEditEmu(String expression) {
		setRegisterValues(thread);

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		editingService.setCurrentMode(tb.trace, StateEditingMode.WRITE_EMULATOR);

		performAction(watchesProvider.actionEnableEdits);

		return row;
	}

	long encodeDouble(double value) {
		ByteBuffer buf = ByteBuffer.allocate(Double.BYTES);
		buf.putDouble(0, value);
		return buf.getLong(0);
	}

	@Test
	public void testEditRegisterEmu() {
		WatchRow row = prepareTestEditEmu("r0");
		TraceMemoryRegisterSpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		row.setRawValueString("0x1234");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			assertEquals(BigInteger.valueOf(0x1234),
				regVals.getValue(viewSnap, r0).getUnsignedValue());
			assertEquals("0x1234", row.getRawValueString());
		});

		row.setRawValueString("1234"); // Decimal this time
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			assertEquals(BigInteger.valueOf(1234),
				regVals.getValue(viewSnap, r0).getUnsignedValue());
			assertEquals("0x4d2", row.getRawValueString());
		});
	}

	@Test
	public void testEditRegisterRepresentationEmu() {
		WatchRow row = prepareTestEditEmu("r0");
		assertFalse(row.isValueEditable());

		row.setDataType(DoubleDataType.dataType);
		waitForSwing();
		assertTrue(row.isValueEditable());

		TraceMemoryRegisterSpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		row.setValueString("1234");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			assertEquals(BigInteger.valueOf(encodeDouble(1234)),
				regVals.getValue(viewSnap, r0).getUnsignedValue());
			assertEquals("0x4093480000000000", row.getRawValueString());
			assertEquals("1234.0", row.getValueString());
		});
	}

	@Test
	public void testEditMemoryEmu() {
		WatchRow row = prepareTestEditEmu("*:8 r0");

		TraceMemoryOperations mem = tb.trace.getMemoryManager();
		ByteBuffer buf = ByteBuffer.allocate(8);

		row.setRawValueString("0x1234");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			buf.clear();
			mem.getBytes(viewSnap, tb.addr(0x00400000), buf);
			buf.flip();
			assertEquals(0x1234, buf.getLong());
		});

		row.setRawValueString("{ 12 34 56 78 9a bc de f0 }");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			buf.clear();
			mem.getBytes(viewSnap, tb.addr(0x00400000), buf);
			buf.flip();
			assertEquals(0x123456789abcdef0L, buf.getLong());
		});
	}

	@Test
	public void testEditMemoryRepresentationEmu() {
		WatchRow row = prepareTestEditEmu("*:8 r0");
		assertFalse(row.isValueEditable());

		row.setDataType(DoubleDataType.dataType);
		waitForSwing();
		assertTrue(row.isValueEditable());

		TraceMemoryOperations mem = tb.trace.getMemoryManager();
		ByteBuffer buf = ByteBuffer.allocate(8);

		row.setValueString("1234");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			buf.clear();
			mem.getBytes(viewSnap, tb.addr(0x00400000), buf);
			buf.flip();
			assertEquals(encodeDouble(1234), buf.getLong());
			assertEquals("1234.0", row.getValueString());
		});
	}

	@Test
	public void testEditMemoryStringEmu() {
		// Variable size must exceed that of desired string's bytes
		WatchRow row = prepareTestEditEmu("*:16 r0");
		assertFalse(row.isValueEditable());

		row.setDataType(TerminatedStringDataType.dataType);
		waitForSwing();
		assertTrue(row.isValueEditable());

		TraceMemoryOperations mem = tb.trace.getMemoryManager();
		ByteBuffer buf = ByteBuffer.allocate(14);

		row.setValueString("\"Hello, World!\"");
		waitForPass(() -> {
			long viewSnap = traceManager.getCurrent().getViewSnap();
			assertTrue(DBTraceUtils.isScratch(viewSnap));
			buf.clear();
			mem.getBytes(viewSnap, tb.addr(0x00400000), buf);
			buf.flip();
			assertArrayEquals("Hello, World!\0".getBytes(), buf.array());
			assertEquals("\"Hello, World!\"", row.getValueString());
		});
	}

	protected WatchRow prepareTestEditTarget(String expression) throws Exception {
		createTestModel();
		mb.createTestProcessesAndThreads();
		bank = mb.testThread1.addRegisterBank();

		mb.testProcess1.regs.addRegistersFromLanguage(tb.language,
			r -> r != r1 && r.isBaseRegister());
		bank.writeRegister("r0", tb.arr(0, 0, 0, 0, 0, 0x40, 0, 0));
		mb.testProcess1.addRegion(".text", mb.rng(0x00400000, 0x00401000), "rx");

		recorder = modelService.recordTarget(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();
		TraceThread thread = waitForValue(() -> recorder.getTraceThread(mb.testThread1));

		traceManager.openTrace(trace);
		traceManager.activateThread(thread);
		editingService.setCurrentMode(trace, StateEditingMode.WRITE_TARGET);
		waitForSwing();

		performAction(watchesProvider.actionAdd);
		WatchRow row = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		row.setExpression(expression);
		performAction(watchesProvider.actionEnableEdits);

		return row;
	}

	@Test
	public void testEditRegisterTarget() throws Throwable {
		WatchRow row = prepareTestEditTarget("r0");

		row.setRawValueString("0x1234");
		retryVoid(() -> {
			assertArrayEquals(mb.arr(0, 0, 0, 0, 0, 0, 0x12, 0x34), bank.regVals.get("r0"));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testEditMemoryTarget() throws Throwable {
		WatchRow row = prepareTestEditTarget("*:8 r0");

		row.setRawValueString("0x1234");
		retryVoid(() -> {
			assertArrayEquals(tb.arr(0, 0, 0, 0, 0, 0, 0x12, 0x34),
				waitOn(mb.testProcess1.memory.readMemory(mb.addr(0x00400000), 8)));
		}, List.of(AssertionError.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEditNonMappableRegisterTarget() throws Throwable {
		WatchRow row = prepareTestEditTarget("r1");
		TraceThread thread = recorder.getTraceThread(mb.testThread1);
		// Sanity check
		assertFalse(recorder.isRegisterOnTarget(thread, r1));

		assertFalse(row.isRawValueEditable());
		row.setRawValueString("0x1234");
	}

	protected void setupUnmappedDataSection() throws Throwable {
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryOperations mem = tb.trace.getMemoryManager();
			mem.createRegion("Memory[bin:.data]", 0, tb.range(0x00600000, 0x0060ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}
		waitForDomainObject(tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	protected void setupMappedDataSection() throws Throwable {
		createProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryOperations mem = tb.trace.getMemoryManager();
			mem.createRegion("Memory[bin:.data]", 0, tb.range(0x55750000, 0x5575ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}
		waitForDomainObject(tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		programManager.openProgram(program);

		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add block", true)) {
			Memory mem = program.getMemory();
			mem.createInitializedBlock(".data", tb.addr(stSpace, 0x00600000), 0x10000,
				(byte) 0, TaskMonitor.DUMMY, false);
		}

		DefaultTraceLocation tloc =
			new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x55750000));
		ProgramLocation ploc = new ProgramLocation(program, tb.addr(stSpace, 0x00600000));
		try (UndoableTransaction tid = tb.startTransaction()) {
			mappingService.addMapping(tloc, ploc, 0x10000, false);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(tloc));
	}

	@Test
	public void testActionWatchViaListingDynamicSelection() throws Throwable {
		setupUnmappedDataSection();

		select(listingProvider,
			tb.set(tb.range(0x00600000, 0x0060000f), tb.range(0x00600020, 0x0060002f)));
		waitForSwing();

		performEnabledAction(listingProvider, watchesProvider.actionAddFromLocation, true);

		List<WatchRow> watches = new ArrayList<>(watchesProvider.watchTableModel.getModelData());
		watches.sort(Comparator.comparing(WatchRow::getExpression));
		assertEquals(2, watches.size());
		assertEquals("*:16 0x00600000:8", watches.get(0).getExpression());
		assertEquals("*:16 0x00600020:8", watches.get(1).getExpression());
	}

	@Test
	public void testActionWatchViaListingStaticSelection() throws Throwable {
		setupMappedDataSection();

		select(codeViewerProvider,
			tb.set(tb.range(0x00600000, 0x0060000f), tb.range(0x00600020, 0x0060002f)));
		waitForSwing();

		performEnabledAction(codeViewerProvider, watchesProvider.actionAddFromLocation, true);

		List<WatchRow> watches = new ArrayList<>(watchesProvider.watchTableModel.getModelData());
		watches.sort(Comparator.comparing(WatchRow::getExpression));
		assertEquals(2, watches.size());
		assertEquals("*:16 0x55750000:8", watches.get(0).getExpression());
		assertEquals("*:16 0x55750020:8", watches.get(1).getExpression());
	}

	@Test
	public void testActionWatchViaListingDynamicDataUnit() throws Throwable {
		setupUnmappedDataSection();

		Structure structDt = new StructureDataType("myStruct", 0);
		structDt.add(DWordDataType.dataType, "field0", "");
		structDt.add(DWordDataType.dataType, "field4", "");

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getCodeManager()
					.definedData()
					.create(Range.atLeast(0L), tb.addr(0x00600000), structDt);
		}

		// TODO: Test with expanded structure?

		performEnabledAction(listingProvider, watchesProvider.actionAddFromLocation, true);

		WatchRow watch = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		assertEquals("*:8 0x00600000:8", watch.getExpression());
		assertTypeEquals(structDt, watch.getDataType());
	}

	@Test
	public void testActionWatchViaListingStaticDataUnit() throws Throwable {
		setupMappedDataSection();
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		Structure structDt = new StructureDataType("myStruct", 0);
		structDt.add(DWordDataType.dataType, "field0", "");
		structDt.add(DWordDataType.dataType, "field4", "");

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add data", true)) {
			program.getListing().createData(tb.addr(stSpace, 0x00600000), structDt);
		}

		// TODO: Test with expanded structure?

		performEnabledAction(codeViewerProvider, watchesProvider.actionAddFromLocation, true);

		WatchRow watch = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		assertEquals("*:8 0x55750000:8", watch.getExpression());
		assertTypeEquals(structDt, watch.getDataType());
	}

	@Test
	public void testActionWatchViaRegisters() throws Throwable {
		addPlugin(tool, DebuggerRegistersPlugin.class);
		DebuggerRegistersProvider registersProvider =
			waitForComponentProvider(DebuggerRegistersProvider.class);
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		RegisterRow rowR0 = registersProvider.getRegisterRow(r0);
		rowR0.setDataType(PointerDataType.dataType);
		registersProvider.setSelectedRow(rowR0);
		waitForSwing();

		performEnabledAction(registersProvider, watchesProvider.actionAddFromRegister, true);

		WatchRow watch = Unique.assertOne(watchesProvider.watchTableModel.getModelData());
		assertEquals("r0", watch.getExpression());
		assertTypeEquals(PointerDataType.dataType, watch.getDataType());
	}
}
