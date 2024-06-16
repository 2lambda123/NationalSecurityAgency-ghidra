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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import generic.test.TestUtils;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/*
 * Tests for the symbol manager that uses database.
 */
public class SymbolManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private SymbolTable st;
	private AddressSpace space;
	private ReferenceManager refMgr;
	private NamespaceManager scopeMgr;
	private int transactionID;
	private Namespace globalScope;
	private Listing listing;

	public SymbolManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		globalScope = program.getGlobalNamespace();
		space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		transactionID = program.startTransaction("Test");
		memory.createInitializedBlock("test", addr(0), 5000, (byte) 0,
			TaskMonitor.DUMMY, false);
		st = program.getSymbolTable();
		refMgr = program.getReferenceManager();
		scopeMgr = program.getNamespaceManager();
		listing = program.getListing();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);
		}
	}

	@Test
	public void testCreateSymbol() throws Exception {
		Symbol s = createLabel(addr(100), "bob");
		assertNotNull(s);
	}

	@Test
	public void testCreateLocal() throws Exception {
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		Symbol s = createLabel(addr(0x200), "printf", scope);
		assertNotNull(s);
	}

	@Test
	public void testGetLocal() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		createLabel(addr(200), "fred", scope);
		Symbol s = st.getSymbol("fred", addr(200), scope);
		assertNotNull(s);
		assertTrue(!s.isGlobal());
		assertTrue(s.getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testGetLocalSymbols() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		createLabel(addr(100), "exit", scope);

		Namespace scope2 = st.createNameSpace(null, "MyNamespace2", SourceType.USER_DEFINED);
		createLabel(addr(200), "exit", scope2);
		createLabel(addr(200), "printf");

		createLabel(addr(256), "exit");

		SymbolIterator it = st.getSymbols("exit");
		int cnt = 0;
		while (it.hasNext()) {
			Symbol s = it.next();
			assertEquals("exit", s.getName());
			cnt++;
		}
		assertEquals(3, cnt);
	}

	@Test
	public void testGetNumSymbols() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		Namespace scope2 = st.createNameSpace(null, "MyNamespace2", SourceType.USER_DEFINED);
		createLabel(addr(100), "exit", scope);
		createLabel(addr(200), "exit", scope2);
		createLabel(addr(200), "printf");
		createLabel(addr(256), "exit");
		assertEquals(9, st.getNumSymbols());
	}

	@Test
	public void testGetPrimarySymbol() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Symbol s = st.getPrimarySymbol(addr(100));
		assertNotNull(s);
		assertEquals("primary", s.getName());
	}

	@Test
	public void testGetAllSymbols() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Symbol[] syms = st.getSymbols(addr(100));
		assertEquals(3, syms.length);
	}

	@Test
	public void testGetByName() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		createLabel(addr(200), "fred", scope);
		Symbol s = getUniqueSymbol(program, "fred");
		assertNotNull(s);
		assertEquals("fred", s.getName());
		assertTrue(s.getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID);
		SymbolIterator it = st.getSymbols("fred");
		int cnt = 0;
		while (it.hasNext()) {
			assertEquals("fred", it.next().getName());
			cnt++;
		}
		assertEquals(2, cnt);

	}

	@Test
	public void testGetSymbolByAddress() throws Exception {
		createLabel(addr(100), "A");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		createLabel(addr(200), "fred", scope);

		Symbol s = st.getSymbol("fred", addr(200), scope);
		assertNotNull(s);
		assertEquals("fred", s.getName());
		assertTrue(!s.isGlobal());
		assertTrue(s.getSource() == SourceType.USER_DEFINED);
		assertTrue(s.isPrimary());
	}

	@Test
	public void testGetSymbolIteratorByAddress() throws Exception {
		createLabel(addr(100), "A");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		createLabel(addr(200), "fred", scope);

		SymbolIterator it = st.getSymbolsAsIterator(addr(100));

		assertTrue(it.hasNext());
		assertEquals("A", it.next().getName());

		assertTrue(it.hasNext());
		assertEquals("fred", it.next().getName());

		assertTrue(it.hasNext());
		assertEquals("joe", it.next().getName());

		assertFalse(it.hasNext());
	}

	@Test
	public void testGetSymbolByReference() throws Exception {
		createLabel(addr(256), "A");
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		Reference ref = refMgr.getReference(addr(512), addr(256), -1);
		Symbol s = st.getSymbol(ref);
		assertNotNull(s);
		assertTrue(s.isPrimary());
	}

	@Test
	public void testGetDynamic() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		Symbol[] s = st.getSymbols(addr(256));
		assertEquals(1, s.length);
		assertTrue(s[0].getSource() == SourceType.DEFAULT);
	}

	@Test
	public void testDynamicNameChangesWhenDataApplied() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		Symbol[] s = st.getSymbols(addr(256));
		assertEquals(1, s.length);
		assertEquals("LAB_00000100", s[0].getName());
		listing.createData(addr(256), new ByteDataType());
		assertEquals("BYTE_00000100", s[0].getName());
	}

	@Test
	public void testDynamicNameChangesWhenDataCleared() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		listing.createData(addr(256), new ByteDataType());
		Symbol[] s = st.getSymbols(addr(256));
		assertEquals(1, s.length);
		assertEquals("BYTE_00000100", s[0].getName());

		listing.clearCodeUnits(addr(256), addr(256), false);
		assertEquals("LAB_00000100", s[0].getName());
	}

	@Test
	public void testDynamicOffcutNameChangesWhenSymbolCreated() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(257), RefType.FLOW, SourceType.USER_DEFINED, -1);
		listing.createData(addr(256), new WordDataType());

		Symbol[] s = st.getSymbols(addr(257));
		assertEquals(1, s.length);
		assertEquals("WORD_00000100+1", s[0].getName());
		st.createLabel(addr(256), "bob", SourceType.USER_DEFINED);
		assertEquals("bob+1", s[0].getName());
	}

	@Test
	public void testDynamicOffcutNameChangesWhenSymbolRenamed() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(257), RefType.FLOW, SourceType.USER_DEFINED, -1);
		listing.createData(addr(256), new WordDataType());
		Symbol label = st.createLabel(addr(256), "bob", SourceType.USER_DEFINED);

		Symbol[] s = st.getSymbols(addr(257));
		assertEquals(1, s.length);
		assertEquals("bob+1", s[0].getName());
		label.setName("fred", SourceType.USER_DEFINED);
		assertEquals("fred+1", s[0].getName());
	}

	@Test
	public void testDynamicOffcutNameChangesWhenSymbolRemoved() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(257), RefType.FLOW, SourceType.USER_DEFINED, -1);
		listing.createData(addr(256), new WordDataType());
		Symbol label = st.createLabel(addr(256), "bob", SourceType.USER_DEFINED);

		Symbol[] s = st.getSymbols(addr(257));
		assertEquals(1, s.length);
		assertEquals("bob+1", s[0].getName());
		label.delete();
		assertEquals("WORD_00000100+1", s[0].getName());
	}

	@Test
	public void testDynamicNameChangesWhenOffcutByInstruction() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(257), RefType.FLOW, SourceType.USER_DEFINED, -1);

		Symbol[] s = st.getSymbols(addr(257));
		assertEquals(1, s.length);
		assertEquals("LAB_00000101", s[0].getName());
		createInstruction(addr(256));
		CodeUnit codeUnitAt = listing.getCodeUnitAt(addr(256));
		assertTrue(codeUnitAt instanceof Instruction);
		assertEquals(2, codeUnitAt.getLength());

		assertEquals("LAB_00000100+1", s[0].getName());
	}

	@Test
	public void testDynamicNameChangesWhenCallRefAdded() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		Symbol[] s = st.getSymbols(addr(256));
		assertEquals(1, s.length);
		assertEquals("LAB_00000100", s[0].getName());

		refMgr.addMemoryReference(addr(512), addr(256), RefType.UNCONDITIONAL_CALL,
			SourceType.USER_DEFINED, -1);

		assertEquals("SUB_00000100", s[0].getName());
	}

	@Test
	public void testDynamicNameChangesWhenCallRefRemoved() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		Reference ref = refMgr.addMemoryReference(addr(516), addr(256), RefType.UNCONDITIONAL_CALL,
			SourceType.USER_DEFINED, -1);

		Symbol[] s = st.getSymbols(addr(256));
		assertEquals(1, s.length);
		assertEquals("SUB_00000100", s[0].getName());

		refMgr.delete(ref);
		assertEquals("LAB_00000100", s[0].getName());
	}

	private void createInstruction(Address addr) throws Exception {
		int tx = program.startTransaction("test");
		try {
			Memory memory = program.getMemory();
			memory.setByte(addr, (byte) 0xd9);
			memory.setByte(addr, (byte) 0x32);
			AddressSet set = new AddressSet(addr, addr.add(1));
			DisassembleCommand cmd = new DisassembleCommand(set, set);
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void testGetDefaultFunctionSymbolByName() throws Exception {

		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(150));
		set.addRange(addr(300), addr(310));
		set.addRange(addr(320), addr(330));
		Function f = listing.createFunction("fredFunc", addr(102), set, SourceType.DEFAULT); // name ignored
		assertNotNull(f);

		String defaultName = "FUN_00000066";
		Symbol s1 = st.getPrimarySymbol(addr(102));
		assertNotNull(s1);
		assertEquals(defaultName, s1.getName());
		assertTrue(s1.isPrimary());

		Symbol s = getUniqueSymbol(program, defaultName);
		assertNotNull(s);
		assertEquals(addr(102), s.getAddress());
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("mem1", "0481:0000", 0x8000);
		builder.createMemoryReference("0481:0000", "0481:00B6", RefType.READ,
			SourceType.USER_DEFINED, 1);
		return builder.getProgram();
	}

	@Test
	public void testSymbolsWithSegmentedAddresses() throws Exception {
		TestEnv env = null;
		Program segmentedProgram = null;
		try {
			env = new TestEnv();
			segmentedProgram = buildProgram("winhelp");
			SymbolTable symbolTable = segmentedProgram.getSymbolTable();
			AddressFactory factory = segmentedProgram.getAddressFactory();
			SegmentedAddressSpace segmentedSpace =
				(SegmentedAddressSpace) factory.getDefaultAddressSpace();
			SegmentedAddress address = segmentedSpace.getAddress(0x0481, 0x00b6);
			Symbol[] symbols = symbolTable.getSymbols(address);
			assertEquals("DAT_0481_00b6", symbols[0].getName());

			TestUtils.invokeInstanceMethod("refresh", symbols[0]);
			assertEquals("DAT_0481_00b6", symbols[0].getName());
		}
		finally {
			env.release(segmentedProgram);
			env.dispose();
		}
	}

	@Test
	public void testGetDefaultFunctionInOverlaySymbolByName() throws Exception {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.createInitializedBlock("ov_12", addr(0), 5000, (byte) 0,
			TaskMonitor.DUMMY, true);
		Address ovAddress = block.getStart();
		assertEquals("ov_12::00000000", ovAddress.toString());

		AddressSet set = new AddressSet(ovAddress, ovAddress);
		Function f = listing.createFunction("fredFunc", ovAddress, set, SourceType.DEFAULT);
		assertNotNull(f);

		String defaultName = "FUN_ov_12__00000000";
		Symbol s1 = st.getPrimarySymbol(ovAddress);
		assertNotNull(s1);
		assertEquals(defaultName, s1.getName());
		assertTrue(s1.isPrimary());

		Symbol s = getUniqueSymbol(program, defaultName);
		assertNotNull(s);
		assertEquals(ovAddress, s.getAddress());
	}

	@Test
	public void testGetDefaultFunctionInOverlaySymbolByNameWith2WordSize() throws Exception {
		Program p = createDefaultProgram("whatever", ProgramBuilder._TOY_WORDSIZE2_BE, this);
		Address address = p.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		int txID = p.startTransaction("test");
		Memory memory = p.getMemory();
		MemoryBlock block = memory.createInitializedBlock("ov12", address, 5000, (byte) 0,
			TaskMonitor.DUMMY, true);
		Address ovAddress = block.getStart();
		assertEquals("ov12::00000000", ovAddress.toString());
		ovAddress = ovAddress.add(2);
		listing = p.getListing();
		st = p.getSymbolTable();

		AddressSet set = new AddressSet(ovAddress, ovAddress);

		Function f = listing.createFunction("fredFunc", ovAddress, set, SourceType.DEFAULT);

		p.endTransaction(txID, true);
		assertNotNull(f);

		String defaultName = "FUN_ov12__00000001";
		Symbol s1 = st.getPrimarySymbol(ovAddress);
		assertNotNull(s1);
		assertEquals(defaultName, s1.getName());
		assertTrue(s1.isPrimary());
	}

	@Test
	public void testRemoveSymbol() throws Exception {
		createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");
		createLabel(addr(100), "bob");
		createLabel(addr(0x200), "A");
		Symbol s = st.getPrimarySymbol(addr(100));
		assertTrue(st.removeSymbolSpecial(s));

		s = st.getPrimarySymbol(addr(100));

		assertEquals("bob", s.getName());
	}

	@Test
	public void testRemoveSymbol2() throws Exception {
		// remove dynamic symbol with refs
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		Symbol sym = st.getPrimarySymbol(addr(256));
		assertTrue(sym.isPrimary());
		assertTrue(sym.getSource() == SourceType.DEFAULT);

		Symbol s2 = createLabel(addr(256), "TEST");
		sym = st.getPrimarySymbol(addr(256));
		assertTrue(sym.isPrimary());
		assertTrue(sym.getSource() != SourceType.DEFAULT);
		st.removeSymbolSpecial(s2);
		sym = st.getPrimarySymbol(addr(256));
		assertTrue(sym.isPrimary());
		assertTrue(sym.getSource() == SourceType.DEFAULT);
	}

	@Test
	public void testRemoveSymbol3() throws Exception {
		// remove non-dynamic, primary symbol without refs
		Symbol sym = createLabel(addr(256), "TEST");
		assertTrue(sym.isPrimary());
		assertTrue(sym.getSource() != SourceType.DEFAULT);
		assertTrue(st.removeSymbolSpecial(sym));
	}

	@Test
	public void testRemoveSymbol5() throws Exception {
		createLabel(addr(256), "TEST1");
		Symbol sym2 = createLabel(addr(256), "TEST2");
		createLabel(addr(256), "TEST3");
		assertTrue(st.removeSymbolSpecial(sym2));
		Symbol[] symbols = st.getSymbols(addr(256));
		assertEquals(2, symbols.length);
		String name1 = symbols[0].getName();
		String name2 = symbols[1].getName();
		assertTrue(name1.equals("TEST1") || name2.equals("TEST1"));
		assertTrue(name1.equals("TEST3") || name2.equals("TEST3"));
	}

	@Test
	public void testRemoveSymbol7() throws Exception {
		Symbol sym1 = createLabel(addr(256), "TEST1");

		Symbol sym2 = createLabel(addr(256), "TEST2");
		Reference ref = refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW,
			SourceType.USER_DEFINED, -1);
		refMgr.setAssociation(sym2, ref);

		assertEquals(0, sym1.getReferenceCount());

		assertTrue(st.removeSymbolSpecial(sym2));

		assertEquals(1, sym1.getReferenceCount());
	}

	@Test
	public void testAddSymbolsWhereNoDefault() throws Exception {
		Address addr = addr(0x0200);

		st.createLabel(addr, "lamp", SourceType.USER_DEFINED);

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("lamp", symbols[0].getName());
		assertEquals(SymbolType.LABEL, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);

		st.createLabel(addr, "shade", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("lamp", symbols[0].getName());
		assertEquals(SymbolType.LABEL, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("shade", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);

	}

	@Test
	public void testAddSymbolWhereDefault() throws Exception {
		Address addr = addr(0x200);
		refMgr.addMemoryReference(addr(0x220), addr(0x200), RefType.FLOW, SourceType.USER_DEFINED,
			0);

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("LAB_00000200", symbols[0].getName());
		assertEquals(SymbolType.LABEL, symbols[0].getSymbolType());
		assertEquals(true, symbols[0].getSource() == SourceType.DEFAULT);

		st.createLabel(addr, "lamp", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("lamp", symbols[0].getName());
		assertEquals(SymbolType.LABEL, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);

		st.removeSymbolSpecial(symbols[0]);

		symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("LAB_00000200", symbols[0].getName());
		assertEquals(SymbolType.LABEL, symbols[0].getSymbolType());
		assertEquals(true, symbols[0].getSource() == SourceType.DEFAULT);

	}

	@Test
	public void testRemoveDefaultSymbol() throws Exception {
		Address addr = addr(0x0200);
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
		assertTrue(cmd.applyTo(program));
		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		boolean removed = st.removeSymbolSpecial(s);
		assertTrue(!removed);// Shouldn't be able to remove default symbol.
		s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		assertEquals("FUN_00000200", s.getName());
	}

	@Test
	public void testAddSymbolsToDefaultFunction() throws Exception {
		Address addr = addr(0x200);
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
		assertTrue(cmd.applyTo(program));
		Symbol s = st.getPrimarySymbol(addr);
		assertNotNull(s);

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("FUN_00000200", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(true, symbols[0].getSource() == SourceType.DEFAULT);

		st.createLabel(addr, "foo", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr);
		assertEquals(1, symbols.length);
		assertEquals("foo", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);

		st.createLabel(addr, "bar", SourceType.USER_DEFINED);

		symbols = st.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("foo", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("bar", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);
	}

	@Test
	public void testRemoveSymbolWhereFunctionIs() throws Exception {
		Address addr = addr(0x0200);
		CreateFunctionCmd cmd =
			new CreateFunctionCmd("MyFunction", addr, null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		st.createLabel(addr, "lamp", SourceType.USER_DEFINED);
		st.createLabel(addr, "shade", SourceType.USER_DEFINED);

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(3, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("lamp", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);
		assertEquals("shade", symbols[2].getName());
		assertEquals(SymbolType.LABEL, symbols[2].getSymbolType());
		assertEquals(false, symbols[2].getSource() == SourceType.DEFAULT);

		Function f = program.getFunctionManager().getFunctionAt(addr);
		assertEquals("MyFunction", f.getSymbol().getName());

		st.removeSymbolSpecial(symbols[1]);

		symbols = st.getSymbols(addr);
		assertEquals(2, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("shade", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);

		f = program.getFunctionManager().getFunctionAt(addr);
		assertEquals("MyFunction", f.getSymbol().getName());
	}

	@Test
	public void testRemoveDefaultFunctionSymbolBeforeFunction() throws Exception {
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0x0200));
		assertTrue(cmd.applyTo(program));
		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		boolean removed = st.removeSymbolSpecial(s);
		assertTrue(!removed);// Shouldn't be able to remove function symbol before function.
		s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		assertEquals("FUN_00000200", s.getName());
	}

	@Test
	public void testRemoveDefaultFunctionSymbolWithFunction() throws Exception {
		CreateFunctionCmd cmd = new CreateFunctionCmd(addr(0x0200));
		assertTrue(cmd.applyTo(program));
		program.getFunctionManager().removeFunction(addr(0x0200));
		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertNull(s);
	}

	@Test
	public void testRemoveFunctionSymbolAfterFunction() throws Exception {
		createFunction("MyFunction", addr(0x0200),
			new AddressSet(addr(0x0200), addr(0x0280)), SourceType.USER_DEFINED);
		program.getFunctionManager().removeFunction(addr(0x0200));
		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		boolean removed = st.removeSymbolSpecial(s);
		assertTrue(removed);// Should be able to remove function symbol after function.
		s = st.getPrimarySymbol(addr(0x0200));
		assertNull(s);
	}

	@Test
	public void testRemoveFunctionBecomesCodeSymbol() throws Exception {
		createFunction("MyFunction", addr(0x0200),
			new AddressSet(addr(0x0200), addr(0x0280)), SourceType.USER_DEFINED);

		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());

		program.getFunctionManager().removeFunction(addr(0x0200));

		s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		assertEquals("MyFunction", s.getName());
		assertEquals(SymbolType.LABEL, s.getSymbolType());

		boolean removed = st.removeSymbolSpecial(s);
		assertTrue(removed);// Should be able to remove function symbol after function.

		s = st.getPrimarySymbol(addr(0x0200));
		assertNull(s);
	}

	@Test
	public void testRemoveFunctionSymbolBecomesExistingCodeSymbol() throws Exception {
		Address entryPt = addr(0x0200);
		createFunction("MyFunction", entryPt,
			new AddressSet(addr(0x0200), addr(0x0280)), SourceType.USER_DEFINED);

		st.createLabel(entryPt, "Bob", SourceType.USER_DEFINED);

		Symbol s = st.getPrimarySymbol(entryPt);
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());
		assertEquals(false, s.getSource() == SourceType.DEFAULT);

		Symbol[] symbols = st.getSymbols(entryPt);
		assertEquals(2, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("Bob", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);

		st.removeSymbolSpecial(s);

		symbols = st.getSymbols(entryPt);
		assertEquals(1, symbols.length);
		assertEquals("Bob", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);

		assertEquals("Bob", program.getFunctionManager().getFunctionAt(entryPt).getName());
	}

	@Test
	public void testRemoveFunctionSymbolBecomesExistingCodeSymbolWithNamespace() throws Exception {
		Namespace oldNamespace = st.createNameSpace(null, "OldNameSpace", SourceType.USER_DEFINED);
		Namespace newNamespace = st.createNameSpace(null, "NewNameSpace", SourceType.USER_DEFINED);
		Address entryPt = addr(0x0200);
		createFunction("MyFunction", entryPt, new AddressSet(addr(0x0200), addr(0x0280)),
			SourceType.USER_DEFINED);
		Symbol functionSym = program.getFunctionManager().getFunctionAt(entryPt).getSymbol();
		Symbol conflictSym = st.createLabel(addr(0x0230), "Bob", SourceType.USER_DEFINED);// put a conflict symbol in.
		conflictSym.setNamespace(oldNamespace);

		Symbol otherSym = st.createLabel(entryPt, "Bob", SourceType.USER_DEFINED);
		functionSym.setNamespace(oldNamespace);
		otherSym.setNamespace(newNamespace);

		Symbol s = st.getPrimarySymbol(entryPt);
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());
		assertEquals(false, s.getSource() == SourceType.DEFAULT);

		Symbol[] symbols = st.getSymbols(entryPt);
		assertEquals(2, symbols.length);
		assertEquals("MyFunction", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(oldNamespace, symbols[0].getParentNamespace());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);
		assertEquals("Bob", symbols[1].getName());
		assertEquals(SymbolType.LABEL, symbols[1].getSymbolType());
		assertEquals(newNamespace, symbols[1].getParentNamespace());
		assertEquals(false, symbols[1].getSource() == SourceType.DEFAULT);

		st.removeSymbolSpecial(s);

		symbols = st.getSymbols(entryPt);
		assertEquals(1, symbols.length);
		assertEquals("Bob", symbols[0].getName());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(newNamespace, symbols[0].getParentNamespace());
		assertEquals(false, symbols[0].getSource() == SourceType.DEFAULT);

		assertEquals("Bob", program.getFunctionManager().getFunctionAt(entryPt).getName());
	}

	@Test
	public void testRemoveFunctionSymbolBecomesDefault() throws Exception {
		createFunction("MyFunction", addr(0x0200),
			new AddressSet(addr(0x0200), addr(0x0280)), SourceType.USER_DEFINED);

		Symbol s = st.getPrimarySymbol(addr(0x0200));
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());
		assertEquals(false, s.getSource() == SourceType.DEFAULT);

		st.removeSymbolSpecial(s);

		s = st.getPrimarySymbol(addr(0x0200));
		assertNotNull(s);
		assertEquals("FUN_00000200", s.getName());
		assertEquals(SymbolType.FUNCTION, s.getSymbolType());
		assertEquals(true, s.getSource() == SourceType.DEFAULT);

		boolean removed = st.removeSymbolSpecial(s);
		assertEquals(false, removed);// Should not be able to remove default function symbol.
	}

	private Function createFunction(String name, Address entry, AddressSetView body,
			SourceType type) {
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, entry, body, type);
		assertTrue(cmd.applyTo(program));
		return cmd.getFunction();
	}

	private Function createFunction(String name, Address entry) {
		AddressSet set = new AddressSet(entry, entry);
		return createFunction(name, entry, set, SourceType.USER_DEFINED);
	}

	@Test
	public void testPrimarySymbolBecomesNonPrimaryAfterFunctionCreated() throws Exception {
		Address addr = addr(256);
		Symbol sym1 = createLabel(addr, "TEST1");
		Symbol sym2 = createLabel(addr, "TEST2");
		Symbol sym3 = createLabel(addr, "TEST3");

		assertEquals(sym1, st.getPrimarySymbol(addr));

		createFunction("TEST_FUN", addr, new AddressSet(addr, addr), SourceType.USER_DEFINED);
		Symbol primary = st.getPrimarySymbol(addr);
		assertEquals("TEST_FUN", primary.getName());
		assertEquals(SymbolType.FUNCTION, primary.getSymbolType());

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(4, symbols.length);

		List<Symbol> list = Arrays.asList(symbols);
		assertTrue(list.contains(primary));
		assertTrue(list.contains(sym1));
		assertTrue(list.contains(sym2));
		assertTrue(list.contains(sym3));

		assertTrue(primary.isPrimary());
		assertFalse(sym1.isPrimary());
		assertFalse(sym2.isPrimary());
		assertFalse(sym3.isPrimary());
	}

	@Test
	public void testPrimarySymbolGetsPromotedToFunction() throws Exception {
		Address addr = addr(256);
		Symbol sym1 = createLabel(addr, "TEST1");
		Symbol sym2 = createLabel(addr, "TEST2");
		Symbol sym3 = createLabel(addr, "TEST3");

		assertEquals(sym1, st.getPrimarySymbol(addr));

		createFunction(null, addr, new AddressSet(addr, addr), SourceType.DEFAULT);
		Symbol primary = st.getPrimarySymbol(addr);
		assertEquals("TEST1", primary.getName());
		assertEquals(SymbolType.FUNCTION, primary.getSymbolType());

		Symbol[] symbols = st.getSymbols(addr);
		assertEquals(3, symbols.length);

		List<Symbol> list = Arrays.asList(symbols);
		assertFalse(list.contains(sym1)); // sym1 was deleted and recreated as a function symbol
		assertTrue(list.contains(primary));
		assertTrue(list.contains(sym2));
		assertTrue(list.contains(sym3));

		assertTrue(primary.isPrimary());
		assertFalse(sym2.isPrimary());
		assertFalse(sym3.isPrimary());

	}

	@Test
	public void testCreateDefaultFunctionWhereDefaultLableExists() {
		Address addr = addr(256);
		refMgr.addMemoryReference(addr(784), addr, RefType.FLOW, SourceType.USER_DEFINED, 2);
		Symbol primary = st.getPrimarySymbol(addr);
		assertNotNull(primary);
		assertEquals(SymbolType.LABEL, primary.getSymbolType());
		assertTrue(primary.getName().startsWith("LAB"));

		createFunction(null, addr, new AddressSet(addr, addr), SourceType.DEFAULT);
		Symbol newPrimary = st.getPrimarySymbol(addr);
		assertTrue(primary != newPrimary);
		assertEquals(SymbolType.FUNCTION, newPrimary.getSymbolType());
		assertTrue(newPrimary.getName().startsWith("FUN"));
		assertTrue(primary.isDeleted());
		assertEquals(1, st.getSymbols(addr).length);
	}

	@Test
	public void testCreateNonDefaultFunctionWhereDefaultLableExists() {
		Address addr = addr(256);
		refMgr.addMemoryReference(addr(784), addr, RefType.FLOW, SourceType.USER_DEFINED, 2);
		Symbol primary = st.getPrimarySymbol(addr);
		assertNotNull(primary);
		assertEquals(SymbolType.LABEL, primary.getSymbolType());
		assertTrue(primary.getName().startsWith("LAB"));

		createFunction("AAA", addr, new AddressSet(addr, addr), SourceType.USER_DEFINED);
		Symbol newPrimary = st.getPrimarySymbol(addr);
		assertTrue(primary != newPrimary);
		assertEquals(SymbolType.FUNCTION, newPrimary.getSymbolType());
		assertEquals("AAA", newPrimary.getName());
		assertTrue(primary.isDeleted());
		assertEquals(1, st.getSymbols(addr).length);
	}

	@Test
	public void testRenameSymbol() throws Exception {
		Symbol s = createLabel(addr(100), "primary");
		createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");

		s.setName("printf", SourceType.USER_DEFINED);
		assertEquals("printf", s.getName());
		assertEquals(s, getUniqueSymbol(program, "printf"));

		try {
			s.setName("fred", SourceType.USER_DEFINED);
			Assert.fail("Expected duplicate name exception");
		}
		catch (DuplicateNameException e) {
			// good
		}
	}

	@Test
	public void testRenameSymbol2() throws Exception {
		// long names (>60) was a problem
		Symbol s = createLabel(addr(100),
			"aabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzABCDEFGH");

		s.setName("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzABCDEFGH1",
			SourceType.USER_DEFINED);
		assertEquals("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzABCDEFGH1", s.getName());
	}

	@Test
	public void testSetPrimary() throws Exception {
		Symbol s1 = createLabel(addr(100), "primary");
		Symbol s2 = createLabel(addr(100), "fred");
		createLabel(addr(100), "joe");

		assertTrue(s1.isPrimary());
		s2.setPrimary();
		assertTrue(s2.isPrimary());
		assertTrue(!s1.isPrimary());

	}

	@Test
	public void testSetScope() throws Exception {
		Symbol s1 = createLabel(addr(100), "primary");
		Symbol s2 = createLabel(addr(100), "fred");
		Symbol s3 = createLabel(addr(100), "joe");

		Namespace scope = st.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		s2.setNamespace(scope);

		assertEquals(scope, s2.getParentNamespace());
		assertEquals(scopeMgr.getGlobalNamespace(), s1.getParentNamespace());
		assertEquals(scopeMgr.getGlobalNamespace(), s3.getParentNamespace());
	}

	@Test
	public void testExternalEntry() throws Exception {
		createLabel(addr(100), "A");
		st.addExternalEntryPoint(addr(100));
		Symbol s = st.getPrimarySymbol(addr(100));
		assertTrue(s.isExternalEntryPoint());

		st.addExternalEntryPoint(addr(100));
		st.addExternalEntryPoint(addr(200));
		st.addExternalEntryPoint(addr(300));
		st.addExternalEntryPoint(addr(400));
		st.addExternalEntryPoint(addr(500));

		assertTrue(st.isExternalEntryPoint(addr(100)));
		assertTrue(st.isExternalEntryPoint(addr(300)));
		assertTrue(st.isExternalEntryPoint(addr(500)));

		assertTrue(!st.isExternalEntryPoint(addr(256)));

		st.removeExternalEntryPoint(addr(300));
		assertTrue(!st.isExternalEntryPoint(addr(300)));

		AddressIterator it = st.getExternalEntryPointIterator();
		it = st.getExternalEntryPointIterator();
		assertEquals(addr(100), it.next());
		assertEquals(addr(200), it.next());
		assertEquals(addr(400), it.next());
		assertEquals(addr(500), it.next());
		assertNull(it.next());
	}

	@Test
	public void testIsExternalEntry() throws Exception {
		createLabel(addr(100), "A");
		st.addExternalEntryPoint(addr(100));
		assertTrue(st.isExternalEntryPoint(addr(100)));
	}

	@Test
	public void testAssociation() throws Exception {
		Symbol sym2 = createLabel(addr(256), "TEST2");

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(784), addr(256), 2);
		refMgr.setAssociation(sym2, ref);
		ref = refMgr.getReference(addr(784), addr(256), 2);
		assertEquals(sym2.getID(), ref.getSymbolID());

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		ref = refMgr.getReference(addr(784), addr(256), -1);
		refMgr.setAssociation(sym2, ref);
		ref = refMgr.getReference(addr(784), addr(256), -1);
		assertEquals(sym2.getID(), ref.getSymbolID());
	}

	@Test
	public void testRemoveAssociation() throws Exception {
		Symbol sym2 = createLabel(addr(256), "TEST2");
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(784), addr(256), 2);
		refMgr.setAssociation(sym2, ref);
		ref = refMgr.getReference(addr(784), addr(256), 2);
		assertEquals(sym2.getID(), ref.getSymbolID());

		refMgr.removeAssociation(ref);
		ref = refMgr.getReference(addr(784), addr(256), 2);
		assertEquals(-1, ref.getSymbolID());
	}

	@Test
	public void testGetSymbolReferences() throws Exception {
		Symbol sym1 = createLabel(addr(256), "TEST1");
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		Symbol sym2 = createLabel(addr(256), "TEST2");
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(784), addr(256), 2);
		refMgr.setAssociation(sym2, ref);
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		ref = refMgr.getReference(addr(784), addr(256), -1);
		refMgr.setAssociation(sym2, ref);
		ReferenceIterator iter = refMgr.getReferencesTo(addr(256));
		ref = iter.next();

		assertNotNull(ref);
		assertEquals(addr(512), ref.getFromAddress());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(1024), ref.getFromAddress());
		assertEquals(0, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(1024), ref.getFromAddress());
		assertEquals(1, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(784), ref.getFromAddress());
		assertEquals(-1, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(784), ref.getFromAddress());
		assertEquals(2, ref.getOperandIndex());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());

		Reference[] refs = refMgr.getReferencesFrom(addr(784));
		assertEquals(2, refs.length);

		assertEquals(2, sym2.getReferenceCount());
		assertEquals(3, sym1.getReferenceCount());
	}

	@Test
	public void testSymbolSearcherIterator() throws Exception {
		createLabel(addr(100), "Four");
		createLabel(addr(100), "Five");
		createLabel(addr(100), "Six");
		createLabel(addr(100), "Seven");
		createLabel(addr(100), "Eight");
		createLabel(addr(100), "Nine");
		createLabel(addr(100), "Thirteen");
		createLabel(addr(200), "Fourteen");
		createLabel(addr(200), "Fifteen");
		createLabel(addr(200), "Sixteen");
		createLabel(addr(200), "Seventeen");
		createLabel(addr(300), "Eighteen");
		createLabel(addr(300), "Nineteen");
		createLabel(addr(300), "Sixty");
		createLabel(addr(300), "Sixty-five");

		List<String> list = search("Six*", true);
		assertContains(list, "Six", "Sixteen", "Sixty", "Sixty-five");

		list = search("*i*n", true);
		assertContains(list, "Thirteen", "Fifteen", "Sixteen", "Eighteen", "Nineteen");

		list = search("*five", false);
		assertContains(list, "Five", "Sixty-five");

		list = search("Five", true);
		assertContains(list, "Five");
	}

	@Test
	public void testSymbolSearcherIterator_WithSymbolNamesContainingWildcards() throws Exception {

		createLabels(addr(100), "Alpha", "alpha", "Albha", "Alzza", "Alibaba", "Alibabas");
		createLabel(addr(100), "Bravo");
		createLabel(addr(100), "Charlie");
		createLabel(addr(200), "Delta");
		createLabels(addr(200), "echo", "echo!bang", "ECHO!bang", "!bangecho", "!bangECHO");
		createLabels(addr(300), "^FOXTROT-hyphen", "^foxtrot-hyphen");
		createLabel(addr(400), "golf,comma");
		createLabel(addr(500), "hotel_underscore");
		createLabel(addr(600), "india.dot.dollar$");
		createLabels(addr(700), "*juliet*", "*JULIET*");
		createLabels(addr(700), "kilo*star", "KILO*star");
		createLabels(addr(800), "lima?questionmark", "LIMA?questionmark");

		boolean caseSensitive = true;

		// no wildcards - escaped asterisk - case-sensitive
		List<String> list = search("\\*juliet\\*", caseSensitive);
		assertContains(list, "*juliet*");

		// no wildcards - escaped asterisk - case-insensitive
		list = search("\\*juliet\\*", !caseSensitive);
		assertContains(list, "*juliet*", "*JULIET*");

		// no wildcards - escaped question mark - case-sensitive
		list = search("lima\\?questionmark", caseSensitive);
		assertContains(list, "lima?questionmark");

		// no wildcards - escaped question mark - case-insensitive
		list = search("lima\\?questionmark", !caseSensitive);
		assertContains(list, "lima?questionmark", "LIMA?questionmark");

		// wildcard - asterisk - case-sensitive
		list = search("*echo*", caseSensitive);
		assertContains(list, "echo", "echo!bang", "!bangecho");

		// wildcard - asterisk - case-insensitive
		list = search("*echo*", !caseSensitive);
		assertContains(list, "echo", "echo!bang", "!bangecho", "ECHO!bang", "!bangECHO");

		// wildcard - question mark - case-sensitive
		list = search("al?ha", caseSensitive);
		assertContains(list, "alpha");

		// wildcard - question mark - case-insensitive
		list = search("al?ha", !caseSensitive);
		assertContains(list, "Alpha", "alpha", "Albha");

		list = search("al*a", !caseSensitive);
		assertContains(list, "Alpha", "alpha", "Albha", "Alzza", "Alibaba");

		// wildcards - escaped asterisk - case-sensitive
		list = search("kilo\\**", caseSensitive);
		assertContains(list, "kilo*star");

		// wildcards - escaped asterisk - case-insensitive
		list = search("kilo\\**", !caseSensitive);
		assertContains(list, "kilo*star", "KILO*star");

		// wildcards - escaped question mark - case-sensitive
		list = search("lima\\?questi?nmark", caseSensitive);
		assertContains(list, "lima?questionmark");

		// wildcards - escaped question mark - case-insensitive
		list = search("li?a\\?questionmark", !caseSensitive);
		assertContains(list, "lima?questionmark", "LIMA?questionmark");

		// wildcards - asterisk and question mark - case-sensitive
		list = search("A*a?", caseSensitive);
		assertContains(list, "Alibabas");

		// wildcards - asterisk and question mark - case-insensitive
		list = search("al*a?", !caseSensitive);
		assertContains(list, "Alibabas");

		// no wildcards - multiple regex-like characters - case-sensitive
		list = search("^foxtrot-hyphen", caseSensitive);
		assertContains(list, "^foxtrot-hyphen");

		// no wildcards - multiple regex-like characters - case-insensitive
		list = search("^foxtrot-hyphen", !caseSensitive);
		assertContains(list, "^FOXTROT-hyphen", "^foxtrot-hyphen");

		// wildcards - consecutive '?' - case-insensitive
		list = search("al??a", !caseSensitive);
		assertContains(list, "Alpha", "alpha", "Albha", "Alzza");

		// wildcards - consecutive '?' - case-sensitive
		list = search("*****c****", caseSensitive);
		assertContains(list, "echo", "echo!bang", "!bangecho", "golf,comma", "hotel_underscore");

		// wildcards - consecutive '?' - case-insensitive
		list = search("*****c****", !caseSensitive);
		assertContains(list, "Charlie", "echo", "echo!bang", "ECHO!bang", "!bangecho", "!bangECHO",
			"golf,comma", "hotel_underscore");

		list = search("*", caseSensitive);
		assertTrue("A wildcard search did not find all symbols - found: " + list, list.size() > 20);
	}

	@Test
	public void testPrimarySymbolIteratorSet() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(200), "2a");
		createLabel(addr(200), "2b");
		createLabel(addr(200), "2c");
		createLabel(addr(300), "3");
		createLabel(addr(300), "3a");
		createLabel(addr(300), "3b");
		createLabel(addr(300), "3c");
		createLabel(addr(400), "4");
		createLabel(addr(500), "5");
		createLabel(addr(500), "5a");
		createFunction(addr(2000), "6");
		createLabel(addr(2000), "6a");
		createExternalFunction("7");
		createExternalLabel("8");

		// test restricted address range
		AddressSet set = new AddressSet(addr(0), addr(50));
		set.addRange(addr(300), addr(350));
		set.addRange(addr(500), addr(1000));
		set.addRange(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
			AddressSpace.EXTERNAL_SPACE.getMaxAddress());
		SymbolIterator it = st.getPrimarySymbolIterator(set, true);

		// External space before memory space
		Symbol s = it.next();
		assertNotNull(s);
		assertEquals("Test::7", s.getName(true));
		assertEquals(extAddr(1), s.getAddress());
		s = it.next();
		assertNotNull(s);
		assertEquals("Test::8", s.getName(true));
		assertEquals(extAddr(2), s.getAddress());

		s = it.next();
		assertNotNull(s);
		assertEquals("3", s.getName(true));
		assertEquals(addr(300), s.getAddress());
		s = it.next();
		assertNotNull(s);
		assertEquals("5", s.getName(true));
		assertEquals(addr(500), s.getAddress());

		assertTrue(!it.hasNext());
		assertNull(it.next());

		// test all memory/external
		it = st.getPrimarySymbolIterator((AddressSetView) null, true);

		assertTrue(it.hasNext());
		s = it.next();
		assertNotNull(s);
		assertEquals("Test::7", s.getName(true));

		assertTrue(it.hasNext());
		s = it.next();
		assertNotNull(s);
		assertEquals("Test::8", s.getName(true));

		for (int i = 1; i <= 6; i++) {
			assertTrue(it.hasNext());
			s = it.next();
			assertNotNull(s);
			assertEquals(Integer.toString(i), s.getName(true));
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testPrimarySymbolIteratorSetBackwards() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(200), "2a");
		createLabel(addr(200), "2b");
		createLabel(addr(200), "2c");
		createLabel(addr(300), "3");
		createLabel(addr(300), "3a");
		createLabel(addr(300), "3b");
		createLabel(addr(300), "3c");
		createLabel(addr(400), "4");
		createLabel(addr(500), "5");
		createLabel(addr(500), "5a");
		createFunction(addr(2000), "6");
		createLabel(addr(2000), "6a");
		createExternalFunction("7");
		createExternalLabel("8");

		AddressSet set = new AddressSet(addr(0), addr(50));
		set.addRange(addr(300), addr(350));
		set.addRange(addr(500), addr(1000));
		set.addRange(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
			AddressSpace.EXTERNAL_SPACE.getMaxAddress());
		SymbolIterator it = st.getPrimarySymbolIterator(set, false);

		Symbol s = it.next();
		assertNotNull(s);
		assertEquals(addr(500), s.getAddress());
		assertEquals("5", s.getName());
		s = it.next();
		assertNotNull(s);
		assertEquals(addr(300), s.getAddress());
		assertEquals("3", s.getName());

		// External space after memory space
		s = it.next();
		assertNotNull(s);
		assertEquals("8", s.getName());
		assertEquals(extAddr(2), s.getAddress());
		s = it.next();
		assertNotNull(s);
		assertEquals("7", s.getName());
		assertEquals(extAddr(1), s.getAddress());

		assertTrue(!it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testSymbolIteratorBackwards() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(200), "2b");
		createLabel(addr(200), "2c");
		createLabel(addr(300), "3");
		createLabel(addr(300), "3a");
		createLabel(addr(300), "3b");
		createLabel(addr(300), "3c");
		createLabel(addr(400), "4");
		createLabel(addr(500), "5");
		createLabel(addr(600), "6");

		SymbolIterator it = st.getSymbolIterator(false);
		assertTrue(it.hasNext());
		Symbol s = it.next();
		assertEquals("6", s.getName());

		assertTrue(it.hasNext());
		s = it.next();
		assertEquals("5", s.getName());

		assertTrue(it.hasNext());
		s = it.next();
		assertEquals("4", s.getName());
	}

	@Test
	public void testPrimarySymbolIterator() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(200), "2a");
		createLabel(addr(200), "2b");
		createLabel(addr(200), "2c");
		createLabel(addr(300), "3");
		createLabel(addr(300), "3a");
		createLabel(addr(300), "3b");
		createLabel(addr(300), "3c");
		createLabel(addr(400), "4");
		createLabel(addr(500), "5");
		createLabel(addr(500), "5a");

		SymbolIterator it = st.getPrimarySymbolIterator(true);
		int count = 1;
		while (it.hasNext()) {
			Symbol sym = it.next();
			assertEquals("" + count, sym.getName());
			count++;
		}
		assertEquals(6, count);
	}

	@Test
	public void testPrimarySymbolIteratorBackwards() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(200), "2a");
		createLabel(addr(200), "2b");
		createLabel(addr(200), "2c");
		createLabel(addr(300), "3");
		createLabel(addr(300), "3a");
		createLabel(addr(300), "3b");
		createLabel(addr(300), "3c");
		createLabel(addr(400), "4");
		createLabel(addr(500), "5");
		createLabel(addr(500), "5a");
		SymbolIterator it = st.getPrimarySymbolIterator(false);

		assertTrue(it.hasNext());

		Symbol s = it.next();
		assertEquals("5", s.getName());

		s = it.next();
		assertEquals("4", s.getName());

		s = it.next();
		assertEquals("3", s.getName());
		s = it.next();
		assertEquals("2", s.getName());

		s = it.next();
		assertEquals("1", s.getName());
	}

	@Test
	public void testSymbolIteratorByType() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(300), "3");
		Function extFunc = createExternalFunction("X");
		createExternalLabel("Y");

		Function f1 = createFunction("A", addr(150));
		Function f2 = createFunction("B", addr(250));

		// test over constrained address set
		AddressSet set = new AddressSet(addr(0), addr(200));
		set.addRange(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
			AddressSpace.EXTERNAL_SPACE.getMaxAddress());

		SymbolIterator it = st.getSymbols(set, SymbolType.FUNCTION, true);

		assertTrue(it.hasNext());
		assertEquals(extFunc.getSymbol(), it.next());

		assertTrue(it.hasNext());
		assertEquals(f1.getSymbol(), it.next());

		assertFalse(it.hasNext());

		it = st.getSymbols(null, SymbolType.FUNCTION, true);

		assertTrue(it.hasNext());
		assertEquals(extFunc.getSymbol(), it.next());

		assertTrue(it.hasNext());
		assertEquals(f1.getSymbol(), it.next());

		assertTrue(it.hasNext());
		assertEquals(f2.getSymbol(), it.next());

		assertFalse(it.hasNext());
	}

	@Test
	public void testSymbolIteratorByTypeBackward() throws Exception {
		createLabel(addr(100), "1");
		createLabel(addr(200), "2");
		createLabel(addr(300), "3");

		Function f1 = createFunction("A", addr(150));
		Function f2 = createFunction("B", addr(250));

		SymbolIterator it =
			st.getSymbols(new AddressSet(addr(0), addr(5000)), SymbolType.FUNCTION, false);

		assertTrue(it.hasNext());
		assertEquals(f2.getSymbol(), it.next());

		assertTrue(it.hasNext());
		assertEquals(f1.getSymbol(), it.next());

		assertFalse(it.hasNext());
	}

	@Test
	public void testAddReference() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.CONDITIONAL_CALL,
			SourceType.USER_DEFINED, 2);

		Symbol s = st.getPrimarySymbol(addr(256));
		assertEquals(SymbolUtilities.getDynamicName(SymbolUtilities.SUB_LEVEL, addr(256)),
			s.getName());

		refMgr.addMemoryReference(addr(200), addr(356), RefType.CONDITIONAL_JUMP,
			SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(200), addr(356), 2);
		createLabel(addr(356), "printf");
		s = st.getSymbol(ref);
		assertNotNull(s);
		assertEquals("printf", s.getName());

	}

	@Test
	public void testRemoveReference() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.CONDITIONAL_CALL,
			SourceType.USER_DEFINED, 2);
		Symbol s = st.getPrimarySymbol(addr(256));

		assertEquals(SymbolUtilities.getDynamicName(SymbolUtilities.SUB_LEVEL, addr(256)),
			s.getName());

		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		refMgr.delete(ref);

		assertNull(st.getPrimarySymbol(addr(256)));

		ref = refMgr.addMemoryReference(addr(200), addr(356), RefType.CONDITIONAL_JUMP,
			SourceType.USER_DEFINED, 2);
		createLabel(addr(356), "printf");
		s = st.getSymbol(ref);
		assertNotNull(s);
		assertEquals("printf", s.getName());

		ref = refMgr.getReference(addr(200), addr(356), 2);
		assertNotNull(ref);
		refMgr.delete(ref);
		ref = refMgr.getReference(addr(200), addr(356), 2);
		assertNull(ref);

	}

	@Test
	public void testCreateFunction() throws Exception {

		Symbol s = createLabel(addr(100), "fred");
		assertTrue(s.isPrimary());

		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(150));
		set.addRange(addr(300), addr(310));
		set.addRange(addr(320), addr(330));
		Function f = createFunction("fredFunc", addr(100), set, SourceType.USER_DEFINED);

		Symbol s1 = st.getPrimarySymbol(addr(100));
		assertNotNull(s1);
		assertEquals("fredFunc", s1.getName());
		assertTrue(s1.isPrimary());

		assertTrue(!s.isPrimary());
		s.setPrimary();
		assertTrue(!s.isPrimary());

		f.setName("fredFuncX", SourceType.USER_DEFINED);
		s = st.getPrimarySymbol(addr(100));
		assertNotNull(s);
		assertEquals("fredFuncX", s.getName());
	}

	@Test
	public void testPromoteLabelToFunctionWithMultipleLabels() throws Exception {

		Symbol s = createLabel(addr(100), "fred");
		assertTrue(s.isPrimary());
		Symbol s2 = createLabel(addr(100), "joe");
		assertTrue(!s2.isPrimary());
		s2.setPrimary();

		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(110));
		Function f = listing.createFunction("joe", addr(100), set, SourceType.USER_DEFINED);

		assertEquals("joe", st.getPrimarySymbol(addr(100)).getName());
		assertTrue(!s.isPrimary());
	}

	@Test
	public void testRenameFunctionToExistingName() throws Exception {

		AddressSet set1 = new AddressSet();
		set1.addRange(addr(100), addr(150));
		Function f1 = listing.createFunction("aaaa", addr(100), set1, SourceType.USER_DEFINED);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(200), addr(250));
		Function f2 = listing.createFunction("bbbb", addr(200), set2, SourceType.USER_DEFINED);

		assertNotNull(f2);
		f2.setName("aaaa", SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getGlobalSymbols("aaaa");
		assertEquals(2, symbols.size());
	}

	@Test
	public void testRemoveFunction() throws Exception {

		Symbol s = createLabel(addr(100), "fred");
		assertFalse(s.isDeleted());

		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(150));
		set.addRange(addr(300), addr(310));
		set.addRange(addr(320), addr(330));
		Function f = listing.createFunction("fredFunc", addr(100), set, SourceType.USER_DEFINED);

		Parameter p = f.addParameter(new ParameterImpl(null, ByteDataType.dataType, program),
			SourceType.DEFAULT);
		Symbol paramSym = p.getSymbol();
		assertFalse(paramSym.isDeleted());

		listing.removeFunction(addr(100));

		assertTrue(paramSym.isDeleted());

		Symbol s1 = st.getPrimarySymbol(addr(100));
		assertNotNull(s1);
		assertEquals("fredFunc", s1.getName());

		f = listing.createFunction("fredFuncX", addr(100), set, SourceType.USER_DEFINED);
		assertEquals("fredFuncX", f.getName());

		assertTrue(!s1.isPrimary());
		assertTrue(!s.isPrimary());
		s1.delete();
		s.delete();

		program.getReferenceManager();

		refMgr.addMemoryReference(addr(0), addr(100), RefType.READ_WRITE, SourceType.USER_DEFINED,
			0);
		listing.removeFunction(addr(100));

		s = st.getPrimarySymbol(addr(100));
		assertNotNull(s);
		assertEquals("fredFuncX", s.getName());

		s.delete();

		s = st.getPrimarySymbol(addr(100));
		assertNotNull(s);
		assertTrue(s.getSource() == SourceType.DEFAULT);
	}

	@Test
	public void testAddExtEntryPoint() throws Exception {
		Symbol s = createLabel(addr(100), "extEntryPoint");
		st.addExternalEntryPoint(addr(100));
		assertEquals("extEntryPoint", s.getName());
		assertTrue(s.isExternalEntryPoint());
	}

	@Test
	public void testRemoveExtEntryPoint() throws Exception {

		Symbol s = createLabel(addr(100), "extEntryPoint");
		st.addExternalEntryPoint(addr(100));
		assertEquals("extEntryPoint", s.getName());
		assertTrue(s.isExternalEntryPoint());

		st.removeExternalEntryPoint(addr(100));
		assertEquals("extEntryPoint", s.getName());
		assertTrue(!s.isExternalEntryPoint());
	}

	@Test
	public void testGetAllSymbolsIncludingDynamic() throws Exception {
		createLabel(addr(0x100), "aaaa");
		createLabel(addr(0x200), "bbbb");
		createLabel(addr(0x300), "cccc");
		refMgr.addMemoryReference(addr(0x40), addr(0x050), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		refMgr.addMemoryReference(addr(0x30), addr(0x150), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		refMgr.addMemoryReference(addr(0x90), addr(0x250), RefType.FLOW, SourceType.USER_DEFINED,
			-1);

		SymbolIterator it = st.getAllSymbols(true);
		assertTrue(it.hasNext());
		assertEquals("LAB_00000050", it.next().getName());
		assertTrue(it.hasNext());
		assertEquals("aaaa", it.next().getName());
		assertTrue(it.hasNext());
		assertEquals("LAB_00000150", it.next().getName());
		assertTrue(it.hasNext());
		assertEquals("bbbb", it.next().getName());
		assertTrue(it.hasNext());
		assertEquals("LAB_00000250", it.next().getName());
		assertTrue(it.hasNext());
		assertEquals("cccc", it.next().getName());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testLabelHistory() throws Exception {
		String[] names = { "primary", "fred", "joe" };

		Address address = addr(100);
		createLabel(address, "primary");
		createLabel(address, "fred");
		createLabel(address, "joe");

		LabelHistory[] h = st.getLabelHistory(address);
		assertEquals(3, h.length);
		String myName = SystemUtilities.getUserName();
		for (int i = 0; i < h.length; i++) {
			assertEquals(LabelHistory.ADD, h[i].getActionID());
			assertEquals(names[i], h[i].getLabelString());
			assertEquals(address, h[i].getAddress());
			assertEquals(myName, h[i].getUserName());
			assertNotNull(h[i].getModificationDate());
		}
	}

	@Test
	public void testLabelHistory2() throws Exception {
		String[] names = { "primary", "fred", "joe", "primary to MyPrimary", "fred", "bob" };
		byte[] actions = { LabelHistory.ADD, LabelHistory.ADD, LabelHistory.ADD,
			LabelHistory.RENAME, LabelHistory.REMOVE, LabelHistory.ADD };

		Address address = addr(100);

		Symbol s1 = createLabel(address, "primary");
		Symbol s2 = createLabel(address, "fred");
		createLabel(address, "joe");

		// rename s1 to
		s1.setName("MyPrimary", SourceType.USER_DEFINED);

		// delete s2
		st.removeSymbolSpecial(s2);

		// create new symbol
		createLabel(addr(100), "bob");

		LabelHistory[] h = st.getLabelHistory(address);
		assertEquals(6, h.length);
		String myName = SystemUtilities.getUserName();
		for (int i = 0; i < h.length; i++) {
			assertEquals(actions[i], h[i].getActionID());
			assertEquals(names[i], h[i].getLabelString());
			assertEquals(address, h[i].getAddress());
			assertEquals(myName, h[i].getUserName());
			assertNotNull(h[i].getModificationDate());
		}

		assertEquals(0, st.getLabelHistory(addr(200)).length);
	}

	@Test
	public void testLabelHistoryIterator() throws Exception {
		String[] names = { "primary", "fred", "joe", "primary to MyPrimary", "fred", "bob",
			"printf", "fprintf" };
		byte[] actions =
			{ LabelHistory.ADD, LabelHistory.ADD, LabelHistory.ADD, LabelHistory.RENAME,
				LabelHistory.REMOVE, LabelHistory.ADD, LabelHistory.ADD, LabelHistory.ADD };
		Address address = addr(100);

		Address[] addrs =
			{ address, address, address, address, address, address, addr(200), addr(200) };

		Symbol s1 = createLabel(address, "primary");
		Symbol s2 = createLabel(address, "fred");
		createLabel(address, "joe");

		// rename s1 to
		s1.setName("MyPrimary", SourceType.USER_DEFINED);

		// delete s2
		st.removeSymbolSpecial(s2);

		// create new symbol
		createLabel(addr(100), "bob");

		createLabel(addr(200), "printf");
		createLabel(addr(200), "fprintf");

		ArrayList<LabelHistory> list = new ArrayList<LabelHistory>();
		Iterator<LabelHistory> iter = st.getLabelHistory();
		assertTrue(iter.hasNext());
		while (iter.hasNext()) {
			LabelHistory h = iter.next();
			list.add(h);
		}
		assertEquals(8, list.size());

		String myName = SystemUtilities.getUserName();

		for (int i = 0; i < list.size(); i++) {
			LabelHistory h = list.get(i);
			assertEquals(actions[i], h.getActionID());
			assertEquals(names[i], h.getLabelString());
			assertEquals(addrs[i], h.getAddress());
			assertEquals(myName, h.getUserName());
			assertNotNull(h.getModificationDate());
		}
	}

	@Test
	public void testLabelHistoryIterator2() {

		Iterator<LabelHistory> iter = st.getLabelHistory();
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testCreateLibScope() throws Exception {
		Namespace scope = st.createExternalLibrary("TestScope", SourceType.USER_DEFINED);
		assertNotNull(scope);
		assertEquals("TestScope", scope.getName());
		assertTrue(scope.getBody().isEmpty());
		assertTrue(scope instanceof Library);
		assertEquals(globalScope, scope.getParentNamespace());

		Symbol symbol = scope.getSymbol();
		assertEquals(scope.getName(), symbol.getName());
		assertEquals(globalScope, symbol.getParentNamespace());
	}

	@Test
	public void testCreateClassScope() throws Exception {
		Namespace scope = st.createClass(null, "TestScope", SourceType.USER_DEFINED);
		assertNotNull(scope);
		assertEquals("TestScope", scope.getName());
		assertTrue(scope.getBody().isEmpty());
		assertTrue(scope instanceof GhidraClass);
		assertEquals(globalScope, scope.getParentNamespace());

		Symbol symbol = scope.getSymbol();
		assertEquals(scope.getName(), symbol.getName());
		assertEquals(globalScope, symbol.getParentNamespace());

		Iterator<GhidraClass> classNamespaces = st.getClassNamespaces();
		assertTrue(classNamespaces.hasNext());
		assertEquals(scope, classNamespaces.next());
		assertTrue(!classNamespaces.hasNext());

		testCreateFunction();// create fredFuncX

		getUniqueSymbol(program, "fredFuncX").setNamespace(scope);

		classNamespaces = st.getClassNamespaces();
		assertTrue(classNamespaces.hasNext());
		assertEquals(scope, classNamespaces.next());
		assertTrue(!classNamespaces.hasNext());
	}

	@Test
	public void testCreateNamespace() throws Exception {
		Namespace scope = st.createNameSpace(null, "TestNameSpace", SourceType.USER_DEFINED);
		assertNotNull(scope);
		assertEquals("TestNameSpace", scope.getName());
		assertTrue(scope.getBody().isEmpty());
		assertEquals(globalScope, scope.getParentNamespace());
		Symbol symbol = scope.getSymbol();
		assertEquals(scope.getName(), symbol.getName());
		assertEquals(globalScope, symbol.getParentNamespace());
	}

	@Test
	public void testSameNamesForNamespaces() throws Exception {
		Namespace s1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		st.createNameSpace(s1, "subspace1", SourceType.USER_DEFINED);
		st.createNameSpace(s1, "subspace2", SourceType.USER_DEFINED);
		st.createNameSpace(s1, "subspace3", SourceType.USER_DEFINED);
		Namespace s2 = st.createNameSpace(null, "MySpace2", SourceType.USER_DEFINED);
		st.createNameSpace(s2, "subspace1", SourceType.USER_DEFINED);
		st.createNameSpace(s2, "subspace2", SourceType.USER_DEFINED);
		st.createNameSpace(s2, "subspace3", SourceType.USER_DEFINED);

		try {
			st.createNameSpace(s2, "subspace3", SourceType.USER_DEFINED);
			Assert.fail("Should have gotten duplicate name exception!");
		}
		catch (DuplicateNameException e) {
			// good
		}
	}

	@Test
	public void testSetSymbolName() throws Exception {

		Symbol s = createLabel(addr(0x100), "mysymbol");
		Namespace s1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		st.createNameSpace(s1, "subspace1", SourceType.USER_DEFINED);
		st.createNameSpace(s1, "fred", SourceType.USER_DEFINED);

		s.setName("fred", SourceType.USER_DEFINED);
		createLabel(addr(0x100), "fred", s1);
		Symbol[] symbols = st.getSymbols(addr(0x100));
		assertEquals(2, symbols.length);
		assertEquals("fred", symbols[0].getName());
		assertEquals(program.getGlobalNamespace(), symbols[0].getParentNamespace());

		assertEquals("fred", symbols[1].getName());
		assertEquals(s1, symbols[1].getParentNamespace());

	}

	@Test
	public void testGetSymbolByNameAndNamespace() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Symbol s1 = st.createLabel(addr(0x100), "Symbol", namespace1, SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("Symbol", namespace1);
		assertEquals(1, symbols.size());
		assertEquals(s1, symbols.get(0));
	}

	@Test
	public void testGetSymbolByNameAndNamespaceWithDupNameInOtherNamespace() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Symbol s1 = st.createLabel(addr(0x100), "Symbol", namespace1, SourceType.USER_DEFINED);

		Namespace namespace2 = st.createNameSpace(null, "MySpace2", SourceType.USER_DEFINED);
		st.createLabel(addr(0x400), "Symbol", namespace2, SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("Symbol", namespace1);
		assertEquals(1, symbols.size());
		assertEquals(s1, symbols.get(0));
	}

	@Test
	public void testGetSymbolByNameAndNamespaceWithDuplicates() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		st.createLabel(addr(0x100), "Symbol", namespace1, SourceType.USER_DEFINED);
		Symbol s2 = st.createLabel(addr(0x200), "SymbolDup", namespace1, SourceType.USER_DEFINED);
		Symbol s3 = st.createLabel(addr(0x300), "SymbolDup", namespace1, SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("SymbolDup", namespace1);
		assertEquals(2, symbols.size());
		assertTrue(symbols.contains(s2));
		assertTrue(symbols.contains(s3));
	}

	@Test
	public void testGetSymbolByNameAndNamespaceWithDuplicatesWithOtherDupsInOtherNamesapce()
			throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		st.createLabel(addr(0x100), "Symbol", namespace1, SourceType.USER_DEFINED);
		Symbol s2 = st.createLabel(addr(0x200), "SymbolDup", namespace1, SourceType.USER_DEFINED);
		Symbol s3 = st.createLabel(addr(0x300), "SymbolDup", namespace1, SourceType.USER_DEFINED);

		Namespace namespace2 = st.createNameSpace(null, "MySpace2", SourceType.USER_DEFINED);
		st.createLabel(addr(0x400), "Symbol", namespace2, SourceType.USER_DEFINED);
		st.createLabel(addr(0x500), "SymbolDup", namespace2, SourceType.USER_DEFINED);
		st.createLabel(addr(0x600), "SymbolDup", namespace2, SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("SymbolDup", namespace1);
		assertEquals(2, symbols.size());
		assertTrue(symbols.contains(s2));
		assertTrue(symbols.contains(s3));
	}

	@Test
	public void testGetSymbolByNameAndNamespaceWithDefaultFunctionNames() throws Exception {
		Namespace namespace = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet body = new AddressSet(addr(0x100), addr(0x150));
		Function f1 =
			listing.createFunction(null, namespace, addr(0x100), body, SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("FUN_00000100", namespace);
		assertEquals(1, symbols.size());
		assertEquals(f1.getSymbol(), symbols.get(0));
	}

	@Test
	public void testGetSymbolByNameAndNamespaceWithDefaultLableNames() {
		refMgr.addMemoryReference(addr(0x200), addr(0x100), RefType.FLOW, SourceType.USER_DEFINED,
			-1);
		Symbol[] symbolArray = st.getSymbols(addr(0x100));
		assertEquals(1, symbolArray.length);
		assertEquals("LAB_00000100", symbolArray[0].getName());

		List<Symbol> symbols = st.getSymbols("LAB_00000100", null);
		assertEquals(1, symbols.size());
		assertEquals(symbolArray[0], symbols.get(0));
	}

	@Test
	public void testGetSymbolNameAndNamespaceInOverlaySpace() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Memory memory = program.getMemory();
		MemoryBlock block = memory.createInitializedBlock("ov_12", addr(0), 5000, (byte) 0,
			TaskMonitor.DUMMY, true);
		Address ovAddress = block.getStart();
		assertEquals("ov_12::00000000", ovAddress.toString());

		AddressSet set = new AddressSet(ovAddress, ovAddress);
		Function f = listing.createFunction(null, namespace1, ovAddress, set, SourceType.DEFAULT);
		assertNotNull(f);

		String defaultName = "FUN_ov_12__00000000";

		List<Symbol> symbols = st.getSymbols(defaultName, namespace1);
		assertEquals(1, symbols.size());
		assertEquals(f.getSymbol(), symbols.get(0));

	}

	@Test
	public void testGetSymbolsByNameNamespaceForLocalVars() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);

		Variable var1 =
			f.addLocalVariable(new LocalVariableImpl("Bob", new IntegerDataType(), 0x8, program),
				SourceType.USER_DEFINED);

		List<Symbol> symbols = st.getSymbols("Bob", f);
		assertEquals(1, symbols.size());
		assertEquals(var1.getSymbol(), symbols.get(0));
	}

	@Test
	public void testGetSymbolsByNameNamespaceForDefaultLocalVars() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);

		Variable var =
			f.addLocalVariable(new LocalVariableImpl(null, new IntegerDataType(), -0x18, program),
				SourceType.DEFAULT);

		List<Symbol> symbols = st.getSymbols("local_18", f);
		assertEquals(1, symbols.size());
		assertEquals(var.getSymbol(), symbols.get(0));
	}

	@Test
	public void testGetSymbolsByNameNamespaceForParams() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		DataType dt = new IntegerDataType();
		Variable param = new ParameterImpl("Bob", dt, program);
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);
		f.updateFunction(f.getCallingConventionName(), null,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED, param);
		Parameter parameter = f.getParameter(0);

		List<Symbol> symbols = st.getSymbols("Bob", f);
		assertEquals(1, symbols.size());
		assertEquals(parameter.getSymbol(), symbols.get(0));
	}

	@Test
	public void testGetSymbolsByNameNamespaceForDefaultParams() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		DataType dt = new IntegerDataType();
		Variable param = new ParameterImpl(null, dt, program);
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);
		f.updateFunction(f.getCallingConventionName(), null,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.DEFAULT, param);

		Parameter parameter = f.getParameter(0);
		List<Symbol> symbols = st.getSymbols("param_1", f);
		assertEquals(1, symbols.size());
		assertEquals(parameter.getSymbol(), symbols.get(0));
	}

	@Test
	public void testGetSymbolByNameNamespaceAddress() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Symbol s1 = st.createLabel(addr(0x100), "Symbol", namespace1, SourceType.USER_DEFINED);

		Symbol symbol = st.getSymbol("Symbol", addr(0x100), namespace1);
		assertEquals(s1, symbol);
	}

	@Test
	public void testGetSymbolByNameNamespaceAddressForDefaultFunction() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);

		Symbol symbol = st.getSymbol("FUN_00000100", addr(0x100), namespace1);
		assertEquals(f.getSymbol(), symbol);
	}

	@Test
	public void testGetSymbolByNameNamespaceAddressForLocalVar() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);

		Variable var =
			f.addLocalVariable(new LocalVariableImpl("Bob", new IntegerDataType(), 0x8, program),
				SourceType.USER_DEFINED);
		Address address = var.getSymbol().getAddress();

		Symbol symbol = st.getSymbol("Bob", address, f);
		assertEquals(var.getSymbol(), symbol);
	}

	@Test
	public void testGetSymbolByNameNamespaceAddressForDefaultLocalVar() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);

		Variable var =
			f.addLocalVariable(new LocalVariableImpl(null, new IntegerDataType(), 0x8, program),
				SourceType.DEFAULT);
		Address address = var.getSymbol().getAddress();
		Symbol symbol = st.getSymbol(var.getName(), address, f);
		assertEquals(var.getSymbol(), symbol);
	}

	@Test
	public void testGetSymbolByNameNamespaceAddressForParam() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		DataType dt = new IntegerDataType();
		Variable param = new ParameterImpl("Bob", dt, program);
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);
		f.updateFunction(f.getCallingConventionName(), null,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED, param);

		Parameter parameter = f.getParameter(0);
		Address address = parameter.getSymbol().getAddress();
		Symbol symbol = st.getSymbol("Bob", address, f);
		assertEquals(parameter.getSymbol(), symbol);
	}

	@Test
	public void testGetSymbolByNameNamespaceAddressForDefaultParam() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		DataType dt = new IntegerDataType();
		Variable param = new ParameterImpl(null, dt, program);
		set.addRange(addr(0x100), addr(0x150));
		Function f =
			listing.createFunction(null, namespace1, addr(0x100), set, SourceType.DEFAULT);
		assertNotNull(f);
		f.updateFunction(f.getCallingConventionName(), null,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.DEFAULT, param);

		Parameter parameter = f.getParameter(0);
		Address address = parameter.getSymbol().getAddress();
		Symbol symbol = st.getSymbol("param_1", address, f);
		assertEquals(parameter.getSymbol(), symbol);
	}

	@Test
	public void testDuplicateSymbol() throws Exception {
		st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		st.createNameSpace(null, "MySpace2", SourceType.USER_DEFINED);

		try {
			st.createClass(program.getGlobalNamespace(), "MySpace1", SourceType.USER_DEFINED);
			Assert.fail("Should have gottenDuplicateName exception!");
		}
		catch (DuplicateNameException e) {
			// good
		}
	}

	@Test
	public void testDuplicateFunctionNames() throws Exception {

		AddressSet set1 = new AddressSet();
		set1.addRange(addr(100), addr(150));
		Function f1 = listing.createFunction("fredFunc", addr(100), set1, SourceType.USER_DEFINED);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(200), addr(250));
		Function f2 = listing.createFunction("fredFunc", addr(200), set2, SourceType.USER_DEFINED);

		assertNotNull(f2);
		List<Symbol> symbols = st.getGlobalSymbols("fredFunc");
		assertEquals(2, symbols.size());
	}

	@Test
	public void testDuplicateNameAtSameAddressDifferentNamespace() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Namespace namespace2 = st.createNameSpace(null, "MySpace2", SourceType.USER_DEFINED);
		st.createLabel(addr(100), "bob", namespace1, SourceType.USER_DEFINED);
		st.createLabel(addr(100), "bob", namespace2, SourceType.USER_DEFINED);
		Symbol[] symbols = st.getSymbols(addr(100));
		assertEquals(2, symbols.length);
		assertEquals("bob", symbols[0].getName());
		assertEquals("bob", symbols[1].getName());
	}

	@Test
	public void testDuplicateNameAtSameAddressSameNamespace() throws Exception {
		Namespace namespace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Symbol s1 = st.createLabel(addr(100), "bob", namespace1, SourceType.USER_DEFINED);
		Symbol s2 = st.createLabel(addr(100), "bob", namespace1, SourceType.USER_DEFINED);
		assertEquals(s1, s2);

		Symbol[] symbols = st.getSymbols(addr(100));
		assertEquals(1, symbols.length);
		assertEquals("bob", symbols[0].getName());
		assertEquals(namespace1, symbols[0].getParentNamespace());
	}

	@Test
	public void testIsDescendant() throws Exception {
		Namespace namespace = st.createNameSpace(null, "TestNameSpace", SourceType.USER_DEFINED);
		Namespace subspace1 = st.createNameSpace(namespace, "MySpace1", SourceType.USER_DEFINED);
		Namespace subspace2 = st.createNameSpace(subspace1, "MySpace2", SourceType.USER_DEFINED);
		Namespace subspace3 = st.createNameSpace(subspace2, "MySpace3", SourceType.USER_DEFINED);

		assertTrue(subspace1.getSymbol().isDescendant(subspace3));
		assertTrue(!subspace3.getSymbol().isDescendant(namespace));
		assertTrue(subspace3.getSymbol().isDescendant(subspace3));
		assertTrue(subspace1.getSymbol().isDescendant(subspace3));
		assertTrue(subspace2.getSymbol().isDescendant(subspace3));
		assertTrue(!subspace2.getSymbol().isDescendant(namespace));
	}

	@Test
	public void testIsValidParentForCodeSymbol() throws Exception {
		Namespace namespace = st.createNameSpace(null, "TestNameSpace", SourceType.USER_DEFINED);
		Symbol s = createLabel(addr(0x125), "printf", namespace);
		Namespace subspace1 = st.createNameSpace(namespace, "MySpace1", SourceType.USER_DEFINED);
		assertTrue(s.isValidParent(subspace1));

		AddressSet set = new AddressSet(addr(0x100), addr(0x150));
		Function f = program.getFunctionManager()
				.createFunction("function_1", addr(0x100), set,
					SourceType.USER_DEFINED);
		assertTrue(s.isValidParent(f));

		Namespace scope = st.createClass(null, "TestScope", SourceType.USER_DEFINED);
		assertTrue(s.isValidParent(scope));

		scope = st.createExternalLibrary("ExtLib", SourceType.USER_DEFINED);
		assertTrue(!s.isValidParent(scope));
	}

	@Test
	public void testIsValidParentForFunction() throws Exception {
		Namespace namespace = st.createNameSpace(null, "TestNameSpace", SourceType.USER_DEFINED);
		createLabel(addr(0x125), "printf", namespace);
		Namespace subspace1 = st.createNameSpace(namespace, "MySpace1", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet(addr(0x100), addr(0x150));
		Function f1 = program.getFunctionManager()
				.createFunction("function_1", addr(0x100), set,
					SourceType.USER_DEFINED);
		set = new AddressSet(addr(0x200), addr(0x250));
		Function f2 = program.getFunctionManager()
				.createFunction("function_2", addr(0x200), set,
					SourceType.USER_DEFINED);

		assertTrue(f1.getSymbol().isValidParent(subspace1));// TestNameSpace::MySpace1::function_1 is OK

		assertTrue(!f1.getSymbol().isValidParent(f1));// self reference invalid
		assertTrue(!f1.getSymbol().isValidParent(f2));// function parent invalid

		Namespace classNs = st.createClass(null, "TestScope", SourceType.USER_DEFINED);
		assertTrue(f1.getSymbol().isValidParent(classNs));
		assertTrue(!classNs.getSymbol().isValidParent(f1));

		f1.getSymbol().setNamespace(classNs);

		assertTrue(subspace1.getSymbol().isValidParent(f1));// TestScope::function_1::MySpace1 is OK
		assertTrue(f2.getSymbol().isValidParent(subspace1));// TestNameSpace::MySpace1::function_1 is OK

		subspace1.setParentNamespace(f1);// TestScope::function_1::MySpace1

		assertEquals("TestScope::function_1::MySpace1", subspace1.getName(true));

		assertTrue(!f2.getSymbol().isValidParent(subspace1));// TestScope::function_1::MySpace1::function_2 is invalid

	}

	@Test
	public void testIsValidParentForNamespace() throws Exception {

		AddressSet set = new AddressSet(addr(0x100), addr(0x150));
		Function f1 = program.getFunctionManager()
				.createFunction("function_1", addr(0x100), set,
					SourceType.USER_DEFINED);

		Namespace namespace = st.createNameSpace(null, "TestNameSpace", SourceType.USER_DEFINED);
		Namespace subspace1 = st.createNameSpace(null, "MySpace1", SourceType.USER_DEFINED);
		Namespace subspace2 = st.createNameSpace(subspace1, "MySpace2", SourceType.USER_DEFINED);
		st.createNameSpace(subspace2, "MySpace3", SourceType.USER_DEFINED);

		assertTrue(subspace2.getSymbol().isValidParent(namespace));// TestNameSpace::MySpace2 is OK
		assertTrue(subspace1.getSymbol().isValidParent(namespace));// TestNameSpace::MySpace2 is OK

		assertTrue(subspace1.getSymbol().isValidParent(f1));// function_1::TestNameSpace::MySpace1 is OK

		Namespace scope = st.createClass(null, "TestScope", SourceType.USER_DEFINED);
		assertTrue(subspace1.getSymbol().isValidParent(scope));// TestScope::MySpace1::MySpace2 is OK

		subspace1.setParentNamespace(scope);

		assertEquals("TestScope::MySpace1::MySpace2", subspace2.getName(true));

	}

	@Test
	public void testClassParentScope() throws Exception {

		Namespace scope = st.createClass(null, "TestClass", SourceType.USER_DEFINED);
		createLabel(addr(0x200), "printf", scope);

	}

	@Test
	public void testInvalidExternalScope() throws Exception {

		Library lib = st.createExternalLibrary("extLib", SourceType.USER_DEFINED);
		ExternalLocation extLoc = program.getExternalManager()
				.addExtFunction("extLib", "printf",
					null, SourceType.USER_DEFINED);
		Symbol extSym = extLoc.getSymbol();
		assertEquals(SymbolType.FUNCTION, extSym.getSymbolType());
		Function extFunc = (Function) extSym.getObject();

		try {
			createLabel(addr(0x200), "printf", extFunc);
			Assert.fail("should have gotten invalid input exception!");
		}
		catch (InvalidInputException e) {
			// good
		}

		Namespace scope = st.createClass(lib, "TestClass", SourceType.USER_DEFINED);
		assertTrue(extSym.isValidParent(scope));
		extFunc.setParentNamespace(scope);

	}

	@Test
	public void testGetUniqueSymbol_NoSymbol() {
		Symbol s = getUniqueSymbol(program, "bob");
		assertNull(s);
	}

	@Test
	public void testGetUniqueSymbol_OneSymbol() throws InvalidInputException {
		Symbol newBob = createLabel(addr(1), "bob");
		Symbol s = getUniqueSymbol(program, "bob");
		assertEquals(newBob, s);
	}

	@Test
	public void testGetUniqueSymbol_MultipleSymbols() throws InvalidInputException {
		createLabel(addr(1), "bob");
		createLabel(addr(2), "bob");
		Symbol s = getUniqueSymbol(program, "bob");
		assertNull(s);
	}

	@Test
	public void testSymbolShortLongIteratorTransition() throws Exception {
		// Exercises the small to large iterator transition
		// See ShortDurationLongKeyIterator -> LongDurationLongKeyIterator transition
		SymbolTable symbolTable = program.getSymbolTable();
		for (long offset = 0; offset < 20; offset++) {
			if (offset != 0) {
				createLabel(addr(offset), "offset" + offset);
			}
			int total = 0;
			for (Symbol s : symbolTable.getAllSymbols(true)) {
				total += 1;
			}
			assertEquals(offset, total);
		}
	}

//==================================================================================================
// Private
//==================================================================================================

	private List<String> search(String text, boolean caseSensitive) {
		SymbolIterator it = st.getSymbolIterator(text, caseSensitive);
		List<String> list = drain(it);
		return list;
	}

	private void assertContains(List<String> list, String... strings) {
		assertListEqualsArrayUnordered(list, (Object[]) strings);
	}

	private List<String> drain(SymbolIterator it) {
		List<String> list = new ArrayList<String>();
		while (it.hasNext()) {
			list.add((it.next()).getName());
		}
		return list;
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private Address extAddr(long l) {
		return AddressSpace.EXTERNAL_SPACE.getAddress(l);
	}

	private Symbol createLabel(Address addr, String name) throws InvalidInputException {
		return st.createLabel(addr, name, SourceType.USER_DEFINED);
	}

	private void createLabels(Address addr, String... names) throws InvalidInputException {

		for (String name : names) {
			st.createLabel(addr, name, SourceType.USER_DEFINED);
		}
	}

	private Symbol createLabel(Address addr, String name, Namespace namespace)
			throws InvalidInputException {
		return st.createLabel(addr, name, namespace, SourceType.USER_DEFINED);
	}

	private Symbol createFunction(Address addr, String name)
			throws InvalidInputException, OverlappingFunctionException {
		return program.getFunctionManager()
				.createFunction(name, addr, new AddressSet(addr, addr), SourceType.USER_DEFINED)
				.getSymbol();
	}

	private Symbol createExternalLabel(String name)
			throws InvalidInputException, DuplicateNameException {
		ExternalManager externalManager = program.getExternalManager();
		return externalManager.addExtLocation("Test", name, null, SourceType.USER_DEFINED)
				.getSymbol();
	}

	private Function createExternalFunction(String name)
			throws InvalidInputException, DuplicateNameException {
		ExternalManager externalManager = program.getExternalManager();
		return externalManager.addExtFunction("Test", name, null, SourceType.USER_DEFINED)
				.getFunction();
	}

}
