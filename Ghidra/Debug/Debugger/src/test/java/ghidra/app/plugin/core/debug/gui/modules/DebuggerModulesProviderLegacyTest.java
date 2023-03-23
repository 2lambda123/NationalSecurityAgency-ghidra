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
package ghidra.app.plugin.core.debug.gui.modules;

import static org.junit.Assert.*;

import java.awt.event.MouseEvent;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.*;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog.MemoryBlockRow;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractImportFromFileSystemAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModuleMapProposalDialog.ModuleMapTableColumns;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapModulesAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapSectionsAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionMapProposalDialog.SectionMapTableColumns;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.attributes.TargetPrimitiveDataType.DefaultTargetPrimitiveDataType;
import ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind;
import ghidra.dbg.model.TestTargetModule;
import ghidra.dbg.model.TestTargetTypedefDataType;
import ghidra.dbg.util.TargetDataTypeConverter;
import ghidra.framework.main.DataTreeDialog;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.util.exception.DuplicateNameException;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerModulesProviderLegacyTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerModulesPlugin modulesPlugin;
	protected DebuggerModulesProvider modulesProvider;

	protected TraceModule modExe;
	protected TraceSection secExeText;
	protected TraceSection secExeData;

	protected TraceModule modLib;
	protected TraceSection secLibText;
	protected TraceSection secLibData;

	@Before
	public void setUpModulesProviderTest() throws Exception {
		modulesPlugin = addPlugin(tool, DebuggerModulesPlugin.class);
		modulesProvider = waitForComponentProvider(DebuggerModulesProvider.class);
	}

	protected void addRegionsFromModules()
			throws TraceOverlappedRegionException, DuplicateNameException {
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager manager = tb.trace.getMemoryManager();
			for (TraceModule module : tb.trace.getModuleManager().getAllModules()) {
				for (TraceSection section : module.getSections()) {
					Set<TraceMemoryFlag> flags = new HashSet<>();
					flags.add(TraceMemoryFlag.READ);
					if (".text".equals(section.getName())) {
						flags.add(TraceMemoryFlag.EXECUTE);
					}
					else if (".data".equals(section.getName())) {
						flags.add(TraceMemoryFlag.WRITE);
					}
					else {
						throw new AssertionError();
					}
					manager.addRegion(
						"Processes[1].Memory[" + module.getName() + ":" + section.getName() + "]",
						module.getLifespan(), section.getRange(), flags);
				}
			}
		}
	}

	protected void addModules() throws Exception {
		TraceModuleManager manager = tb.trace.getModuleManager();
		try (Transaction tx = tb.startTransaction()) {
			modExe = manager.addLoadedModule("Processes[1].Modules[first_proc]", "first_proc",
				tb.range(0x55550000, 0x5575007f), 0);
			secExeText = modExe.addSection("Processes[1].Modules[first_proc].Sections[.text]",
				".text", tb.range(0x55550000, 0x555500ff));
			secExeData = modExe.addSection("Processes[1].Modules[first_proc].Sections[.data]",
				".data", tb.range(0x55750000, 0x5575007f));

			modLib = manager.addLoadedModule("Processes[1].Modules[some_lib]", "some_lib",
				tb.range(0x7f000000, 0x7f10003f), 0);
			secLibText = modLib.addSection("Processes[1].Modules[some_lib].Sections[.text]",
				".text", tb.range(0x7f000000, 0x7f0003ff));
			secLibData = modLib.addSection("Processes[1].Modules[some_lib].Sections[.data]",
				".data", tb.range(0x7f100000, 0x7f10003f));
		}
	}

	protected MemoryBlock addBlock() throws Exception {
		try (Transaction tx = program.openTransaction("Add block")) {
			return program.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x1000, (byte) 0, monitor,
						false);
		}
	}

	protected void assertProviderEmpty() {
		List<ModuleRow> modulesDisplayed =
			modulesProvider.legacyModulesPanel.moduleTableModel.getModelData();
		assertTrue(modulesDisplayed.isEmpty());

		List<SectionRow> sectionsDisplayed =
			modulesProvider.legacySectionsPanel.sectionTableModel.getModelData();
		assertTrue(sectionsDisplayed.isEmpty());
	}

	protected void assertProviderPopulated() {
		List<ModuleRow> modulesDisplayed =
			new ArrayList<>(modulesProvider.legacyModulesPanel.moduleTableModel.getModelData());
		modulesDisplayed.sort(Comparator.comparing(r -> r.getBase()));
		// I should be able to assume this is sorted by base address. It's the default sort column.
		assertEquals(2, modulesDisplayed.size());

		ModuleRow execRow = modulesDisplayed.get(0);
		assertEquals(tb.addr(0x55550000), execRow.getBase());
		assertEquals("first_proc", execRow.getName());

		// Use only (start) offset for excess, as unique ID
		ModuleRow libRow = modulesDisplayed.get(1);
		assertEquals(tb.addr(0x7f000000), libRow.getBase());

		List<SectionRow> sectionsDisplayed =
			new ArrayList<>(modulesProvider.legacySectionsPanel.sectionTableModel.getModelData());
		sectionsDisplayed.sort(Comparator.comparing(r -> r.getStart()));
		assertEquals(4, sectionsDisplayed.size());

		SectionRow execTextRow = sectionsDisplayed.get(0);
		assertEquals(tb.addr(0x55550000), execTextRow.getStart());
		assertEquals(tb.addr(0x555500ff), execTextRow.getEnd());
		assertEquals("first_proc", execTextRow.getModuleName());
		assertEquals(".text", execTextRow.getName());
		assertEquals(256, execTextRow.getLength());

		SectionRow execDataRow = sectionsDisplayed.get(1);
		assertEquals(tb.addr(0x55750000), execDataRow.getStart());

		SectionRow libTextRow = sectionsDisplayed.get(2);
		assertEquals(tb.addr(0x7f000000), libTextRow.getStart());

		SectionRow libDataRow = sectionsDisplayed.get(3);
		assertEquals(tb.addr(0x7f100000), libDataRow.getStart());
	}

	@Test
	public void testEmpty() throws Exception {
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testActivateThenAddModulesPopulatesProvider() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		addModules();
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testAddModulesThenActivatePopulatesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		waitForSwing();

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testBlockChooserDialogPopulates() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		runSwing(() -> modulesProvider.setSelectedSections(Set.of(secExeText)));
		performEnabledAction(modulesProvider, modulesProvider.actionMapSections, false);

		DebuggerSectionMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerSectionMapProposalDialog.class);
		clickTableCell(propDialog.getTable(), 0, SectionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);

		assertEquals(1, blockDialog.getTableModel().getRowCount());
		MemoryBlockRow row = blockDialog.getTableModel().getModelData().get(0);
		assertEquals(program, row.getProgram());
		assertEquals(block, row.getBlock());
		// NOTE: Other getters should be tested in a separate MemoryBlockRowTest

		pressButtonByText(blockDialog, "Cancel", true);
	}

	@Test
	public void testRemoveModulesRemovedFromProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		try (Transaction tx = tb.startTransaction()) {
			modExe.delete();
		}
		waitForDomainObject(tb.trace);

		List<ModuleRow> modulesDisplayed =
			new ArrayList<>(modulesProvider.legacyModulesPanel.moduleTableModel.getModelData());
		modulesDisplayed.sort(Comparator.comparing(r -> r.getBase()));
		assertEquals(1, modulesDisplayed.size());

		ModuleRow libRow = modulesDisplayed.get(0);
		assertEquals("some_lib", libRow.getName());

		List<SectionRow> sectionsDisplayed =
			new ArrayList<>(modulesProvider.legacySectionsPanel.sectionTableModel.getModelData());
		sectionsDisplayed.sort(Comparator.comparing(r -> r.getStart()));
		assertEquals(2, sectionsDisplayed.size());

		SectionRow libTextRow = sectionsDisplayed.get(0);
		assertEquals(".text", libTextRow.getName());
		assertEquals("some_lib", libTextRow.getModuleName());

		SectionRow libDataRow = sectionsDisplayed.get(1);
		assertEquals(".data", libDataRow.getName());
		assertEquals("some_lib", libDataRow.getModuleName());
	}

	@Test
	public void testUndoRedoCausesUpdateInProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		undo(tb.trace);
		assertProviderEmpty();

		redo(tb.trace);
		assertProviderPopulated();
	}

	@Test
	public void testActivatingNoTraceEmptiesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		traceManager.activateTrace(null);
		waitForSwing();
		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertProviderPopulated();
	}

	@Test
	public void testCurrentTraceClosedEmptiesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		traceManager.closeTrace(tb.trace);
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testActionMapIdentically() throws Exception {
		assertFalse(modulesProvider.actionMapIdentically.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		// No modules necessary
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(modulesProvider.actionMapIdentically.isEnabled());

		// Need some substance in the program
		try (Transaction tx = program.openTransaction("Populate")) {
			addBlock();
		}
		waitForDomainObject(program);

		performEnabledAction(modulesProvider, modulesProvider.actionMapIdentically, true);
		waitForDomainObject(tb.trace);

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x1000, sm.getLength()); // Block is 0x1000 in length
		assertEquals(tb.addr(0x00400000), sm.getMinTraceAddress());
	}

	@Test
	public void testActionMapModules() throws Exception {
		assertFalse(modulesProvider.actionMapModules.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertFalse(modulesProvider.actionMapModules.isEnabled());

		try (Transaction tx = program.openTransaction("Change name")) {
			program.setImageBase(addr(program, 0x00400000), true);
			program.setName(modExe.getName());

			addBlock(); // So the program has a size
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		assertTrue(modulesProvider.actionMapModules.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionMapModules, false);

		DebuggerModuleMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerModuleMapProposalDialog.class);

		List<ModuleMapEntry> proposal = propDialog.getTableModel().getModelData();
		ModuleMapEntry entry = Unique.assertOne(proposal);
		assertEquals(modExe, entry.getModule());
		assertEquals(program, entry.getToProgram());

		clickTableCell(propDialog.getTable(), 0, ModuleMapTableColumns.CHOOSE.ordinal(), 1);

		DataTreeDialog programDialog = waitForDialogComponent(DataTreeDialog.class);
		assertEquals(program.getDomainFile(), programDialog.getDomainFile());

		pressButtonByText(programDialog, "OK", true);

		assertEquals(program, entry.getToProgram());
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x1000, sm.getLength()); // Block is 0x1000 in length
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());
	}

	// TODO: testActionMapModulesTo
	// TODO: testActionMapModuleTo

	@Test
	public void testActionMapSections() throws Exception {
		assertFalse(modulesProvider.actionMapSections.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertFalse(modulesProvider.actionMapSections.isEnabled());

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		modulesProvider.setSelectedSections(Set.of(secExeText));
		waitForSwing();
		assertTrue(modulesProvider.actionMapSections.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionMapSections, false);

		DebuggerSectionMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerSectionMapProposalDialog.class);

		List<SectionMapEntry> proposal = propDialog.getTableModel().getModelData();
		SectionMapEntry entry = Unique.assertOne(proposal);
		assertEquals(secExeText, entry.getSection());
		assertEquals(block, entry.getBlock());

		clickTableCell(propDialog.getTable(), 0, SectionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);
		MemoryBlockRow row = Unique.assertOne(blockDialog.getTableModel().getModelData());
		assertEquals(block, row.getBlock());

		pressButtonByText(blockDialog, "OK", true);
		assertEquals(block, entry.getBlock()); // Unchanged
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x100, sm.getLength()); // Section is 0x100, though block is 0x1000 long
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());
	}

	// TODO: testActionMapSectionsTo
	// TODO: testActionMapSectionTo

	@Test
	public void testActionSelectAddresses() throws Exception {
		assertFalse(modulesProvider.actionSelectAddresses.isEnabled());

		addPlugin(tool, DebuggerListingPlugin.class);
		waitForComponentProvider(DebuggerListingProvider.class);
		// TODO: Should I hide the action if this service is missing?
		DebuggerListingService listing = tool.getService(DebuggerListingService.class);
		createAndOpenTrace();

		addModules();
		addRegionsFromModules();

		// Still
		assertFalse(modulesProvider.actionSelectAddresses.isEnabled());

		traceManager.activateTrace(tb.trace);
		waitForSwing(); // NOTE: The table may select first by default, enabling action
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));
		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		assertTrue(modulesProvider.actionSelectAddresses.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x55750000, 0x5575007f)),
			new AddressSet(listing.getCurrentSelection()));

		modulesProvider.setSelectedSections(Set.of(secExeText, secLibText));
		waitForSwing();
		assertTrue(modulesProvider.actionSelectAddresses.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x7f000000, 0x7f0003ff)),
			new AddressSet(listing.getCurrentSelection()));
	}

	@Test
	@Ignore("This action is hidden until supported")
	public void testActionCaptureTypes() throws Exception {
		assertFalse(modulesProvider.actionCaptureTypes.isEnabled());
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		// TODO: A region should not be required first. Just to get a memMapper?
		mb.testProcess1.addRegion("Memory[first_proc:.text]", mb.rng(0x55550000, 0x555500ff),
			"rx");
		TestTargetModule module =
			mb.testProcess1.modules.addModule("Modules[first_proc]",
				mb.rng(0x55550000, 0x555500ff));
		// NOTE: A section should not be required at this point.
		TestTargetTypedefDataType typedef = module.types.addTypedefDataType("myInt",
			new DefaultTargetPrimitiveDataType(PrimitiveKind.SINT, 4));
		waitForDomainObject(trace);

		// Still
		assertFalse(modulesProvider.actionCaptureTypes.isEnabled());

		traceManager.activateTrace(trace);
		waitForSwing();
		TraceModule traceModule = waitForValue(() -> recorder.getTraceModule(module));
		modulesProvider.setSelectedModules(Set.of(traceModule));
		waitForSwing();
		// TODO: When action is included, put this assertion back
		//assertTrue(modulesProvider.actionCaptureTypes.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionCaptureTypes, true);
		waitForBusyTool(tool);
		waitForDomainObject(trace);

		// TODO: A separate action/script to transfer types from trace DTM into mapped program DTMs
		TraceBasedDataTypeManager dtm = trace.getDataTypeManager();
		TargetDataTypeConverter conv = new TargetDataTypeConverter(dtm);
		DataType expType =
			conv.convertTargetDataType(typedef).get(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS);
		// TODO: Some heuristic or convention to extract the module name, if applicable
		waitForPass(() -> {
			DataType actType = dtm.getDataType("/Modules[first_proc].Types/myInt");
			assertTypeEquals(expType, actType);
		});

		// TODO: When capture-types action is included, put this assertion back
		//assertTrue(modulesProvider.actionCaptureTypes.isEnabled());
		waitForLock(trace);
		recorder.stopRecording();
		waitForSwing();
		assertFalse(modulesProvider.actionCaptureTypes.isEnabled());
	}

	@Test
	public void testActionCaptureSymbols() throws Exception {
		assertFalse(modulesProvider.actionCaptureSymbols.isEnabled());
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		// TODO: A region should not be required first. Just to get a memMapper?
		mb.testProcess1.addRegion("first_proc:.text", mb.rng(0x55550000, 0x555500ff),
			"rx");
		TestTargetModule module =
			mb.testProcess1.modules.addModule("first_proc", mb.rng(0x55550000, 0x555500ff));
		// NOTE: A section should not be required at this point.
		module.symbols.addSymbol("test", mb.addr(0x55550080), 8,
			new DefaultTargetPrimitiveDataType(PrimitiveKind.UNDEFINED, 8));
		waitForDomainObject(trace);

		// Still
		assertFalse(modulesProvider.actionCaptureSymbols.isEnabled());

		traceManager.activateTrace(trace);
		waitForSwing();
		waitForPass(() -> {
			TraceModule traceModule = recorder.getTraceModule(module);
			assertNotNull(traceModule);
			modulesProvider.setSelectedModules(Set.of(traceModule));
			waitForSwing();
			assertTrue(modulesProvider.actionCaptureSymbols.isEnabled());
		});

		performEnabledAction(modulesProvider, modulesProvider.actionCaptureSymbols, true);
		waitForBusyTool(tool);
		waitForDomainObject(trace);

		// TODO: A separate action/script to transfer symbols from trace into mapped programs
		// NOTE: Used types must go along.
		Collection<? extends TraceSymbol> symbols =
			trace.getSymbolManager().allSymbols().getNamed("test");
		assertEquals(1, symbols.size());
		TraceSymbol sym = symbols.iterator().next();
		// TODO: Some heuristic or convention to extract the module name, if applicable
		assertEquals("Processes[1].Modules[first_proc].Symbols::test", sym.getName(true));
		// NOTE: builder (b) is not initialized here
		assertEquals(trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(0x55550080),
			sym.getAddress());
		// TODO: Check data type once those are captured in Data units.

		assertTrue(modulesProvider.actionCaptureSymbols.isEnabled());
		waitForLock(trace);
		recorder.stopRecording();
		waitForSwing();
		assertFalse(modulesProvider.actionCaptureSymbols.isEnabled());
	}

	@Test
	public void testActionImportFromFileSystem() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		try (Transaction tx = tb.startTransaction()) {
			modExe.setName("/bin/echo"); // File has to exist
		}
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		performAction(modulesProvider.actionImportFromFileSystem, false);

		GhidraFileChooser dialog = waitForDialogComponent(GhidraFileChooser.class);
		dialog.close();
	}

	protected Set<SectionRow> visibleSections() {
		return Set
				.copyOf(modulesProvider.legacySectionsPanel.sectionFilterPanel.getTableFilterModel()
						.getModelData());
	}

	@Test
	public void testActionFilterSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		assertEquals(4, visibleSections().size());

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();

		assertEquals(4, visibleSections().size());

		assertTrue(modulesProvider.actionFilterSectionsByModules.isEnabled());
		performEnabledAction(modulesProvider, modulesProvider.actionFilterSectionsByModules, true);
		waitForSwing();

		assertEquals(2, visibleSections().size());
		for (SectionRow row : visibleSections()) {
			assertEquals(modExe, row.getModule());
		}

		modulesProvider.setSelectedModules(Set.of());
		waitForSwing();

		waitForPass(() -> assertEquals(4, visibleSections().size()));
	}

	protected static final Set<String> POPUP_ACTIONS = Set.of(AbstractSelectAddressesAction.NAME,
		DebuggerResources.NAME_MAP_MODULES, DebuggerResources.NAME_MAP_SECTIONS,
		AbstractImportFromFileSystemAction.NAME);

	@Test
	public void testPopupActionsOnModuleSelections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		// NB. Table is debounced
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		clickTableCellWithButton(modulesProvider.legacyModulesPanel.moduleTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));

		pressEscape();

		addPlugin(tool, ImporterPlugin.class);
		waitForSwing();
		clickTableCellWithButton(modulesProvider.legacyModulesPanel.moduleTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME, AbstractImportFromFileSystemAction.NAME));
	}

	@Test
	public void testPopupActionsOnSectionSelections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		clickTableCellWithButton(modulesProvider.legacySectionsPanel.sectionTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));
	}
}
