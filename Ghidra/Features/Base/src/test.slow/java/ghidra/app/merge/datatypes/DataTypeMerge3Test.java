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
package ghidra.app.merge.datatypes;

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Test;

import docking.widgets.OptionDialog;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * More data type merge tests.
 * 
 * 
 */
public class DataTypeMerge3Test extends AbstractDataTypeMergeTest {

	@Test
	public void testDeleteUnionComponent() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					// 2 components should get removed from CoolUnion
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					union.add(new FloatDataType());
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// choose MY
		chooseOption(DataTypeMergeManager.OPTION_MY);// DLL_Table from MY

		// then choose LATEST
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion

		waitForCompletion();

		// DLL_Table should have a Word data type as the last component
		Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		DataTypeComponent dtc = s.getComponent(s.getNumComponents() - 1);
		assertTrue(dtc.getDataType().isEquivalent(new WordDataType()));

		// CoolUnion should not have DLL_Table components
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(3, dtcs.length);
		DataType dt = dtcs[2].getDataType();
		assertTrue(dt instanceof Pointer);

		// DLL_Table should have Word added to it
		dtcs = s.getDefinedComponents();
		assertEquals(9, dtcs.length);
		assertTrue(dtcs[8].getDataType().isEquivalent(new WordDataType()));
	}

	@Test
	public void testDeleteUnionComponent2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					// 2 components should get removed from CoolUnion
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// choose DLL_Table from LATEST which means delete it
		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		// MY CoolUnion
		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// DLL_Table should not exist
		assertNull(dtm.getDataType(CategoryPath.ROOT, "DLL_Table"));

		// CoolUnion should not have DLL_Table components but should have Float 
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(4, dtcs.length);
		DataType dt = dtcs[3].getDataType();
		assertTrue(dt.isEquivalent(new FloatDataType()));
		assertEquals("my comments", dtcs[3].getComment());
		assertEquals("Float Field", dtcs[3].getFieldName());
	}

	@Test
	public void testDeleteUnionComponent3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					// 2 components should get removed from CoolUnion
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose DLL_Table from ORIGINAL

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// DLL_Table should exist
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// CoolUnion should not have DLL_Table components but should have Float 
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertEquals(dll, dtcs[3].getDataType());
		DataType dt = dtcs[5].getDataType();
		assertTrue(dt.isEquivalent(new FloatDataType()));
		assertEquals("my comments", dtcs[5].getComment());
		assertEquals("Float Field", dtcs[5].getFieldName());
	}

	@Test
	public void testStructureUpdateFailure() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(dt);
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		setErrorsExpected(true);

		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		checkConflictCount(0);

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] fooComps = foo.getComponents();
		assertEquals(6, fooComps.length);

		// Foo should not contain CoolUnion because CoolUnion already 
		// contains Foo (from Latest)
		assertEquals("Foo", coolUnionComps[5].getDataType().getDisplayName());

		// Foo.conflict should contain CoolUnion.conflict because CoolUnion already 
		// contains Foo (from Latest), so Foo (From My) becomes Foo.conflict and its
		// original CoolUnion becomes CoolUnion.conflict.
		assertEquals("float", fooComps[5].getDataType().getDisplayName());
		assertTrue(fooComps[4].getDataType() instanceof BadDataType);
		assertTrue(fooComps[4].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testStructureUpdateFailure2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
					// Edit Foo to cause a conflict
					foo.add(new ByteDataType());

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(union);
					foo.add(new FloatDataType());
					// Edit CoolUnion to cause a conflict
					union.add(new FloatDataType(), "My Float", "My comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		setErrorsExpected(true);

		executeMerge();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY Foo
		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] fooComps = foo.getComponents();
		assertEquals(6, fooComps.length);

		// Foo should not contain CoolUnion because CoolUnion already 
		// contains Foo (from Latest)
		assertEquals("Foo", coolUnionComps[5].getDataType().getDisplayName());

		// Foo.conflict should contain CoolUnion.conflict because CoolUnion already 
		// contains Foo (from Latest), so Foo (From My) becomes Foo.conflict and its
		// original CoolUnion becomes CoolUnion.conflict.
		assertEquals("float", fooComps[5].getDataType().getDisplayName());
		assertTrue(fooComps[4].getDataType() instanceof BadDataType);
		assertTrue(fooComps[4].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testStructureUpdateFailure3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
					// Edit Foo to cause a conflict
					foo.add(new ByteDataType());

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(union);
					foo.add(new FloatDataType());
					// Edit CoolUnion to cause a conflict
					union.add(new FloatDataType(), "My Float", "My comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		setErrorsExpected(true);

		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST Foo

		waitForCompletion();

		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertTrue(dtcs[5].getDataType().isEquivalent(new FloatDataType()));

		// Foo from Latest
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new ByteDataType()));
		checkConflictCount(0);
	}

	@Test
	public void testStructureUpdateFailure4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					union.add(bar, "My field name", "My comments");

					bar.add(new ByteDataType());

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(union);
					union.add(new ByteDataType(), "my field name", "some comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		setErrorsExpected(true);

		executeMerge();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Latest CoolUnion
		chooseOption(DataTypeMergeManager.OPTION_MY);// My Bar

		//
		// This last choice shows an error dialog
		//
		OptionDialog errorDialog =
			waitForDialogComponent(null, OptionDialog.class, DEFAULT_WINDOW_TIMEOUT);
		assertNotNull(errorDialog);
		errorDialog.close();
		window.setVisible(false);

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(coolUnion);
		assertNotNull(bar);

		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);
		DataTypeComponent[] barComps = bar.getDefinedComponents();
		assertEquals(3, barComps.length);

		assertEquals(bar, coolUnionComps[5].getDataType());
		assertEquals("My field name", coolUnionComps[5].getFieldName());
		assertEquals("My comments", coolUnionComps[5].getComment());

		assertTrue(barComps[2].getDataType() instanceof BadDataType);
		assertTrue(barComps[2].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testConflictUpdate() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		setErrorsExpected(true);

		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		//
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose My Bar

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);
		// choose Structure_1 from ORIGINAL

		waitForCompletion();
		// Bar should contain original Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		DataTypeComponent[] dtcs = bar.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertTrue(dtcs[2].getDataType().isEquivalent(new ByteDataType()));
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		dtcs = s1.getComponents();
		assertEquals(4, dtcs.length);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[2].getDataType());

		dtcs = foo.getComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new FloatDataType()));
		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					// causes Bar to be marked as changed
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		//
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose original Bar

		chooseOption(DataTypeMergeManager.OPTION_MY);
		// choose Structure_1 from MY

		waitForCompletion();
		// Bar should contain original Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertEquals(6, bar.getLength());
		DataTypeComponent[] dtcs = bar.getComponents();
		assertEquals(2, dtcs.length);
		DataType dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Pointer);

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		assertEquals(s1, ((Pointer) dt).getDataType());

		dtcs = s1.getComponents();
		assertEquals(3, dtcs.length);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[2].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();

				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					// causes Bar to be marked as changed
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		//
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose my Bar

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delele Structure_1 
		// choose Structure_1 from MY

		waitForCompletion();
		// Bar should contain undefined to replace Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertEquals(7, bar.getLength());
		DataTypeComponent[] dtcs = bar.getComponents();
		assertEquals(6, dtcs.length);
		for (int i = 1; i < 5; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}

		// Structure_1 should have been deleted
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNull(s1);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		assertEquals(bar, dtcs[3].getDataType());
		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();

				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
					"FloatStruct");
				Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					Structure s1 = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category5"), "s1", 0);
					s1.add(ms);
					s1 = (Structure) dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);
					s1.add(new ByteDataType());
					Pointer p = PointerDataType.getPointer(a, 4);
					s1.add(p);

					// edit ArrayStruct
					a.add(s1);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
						"FloatStruct");
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
				try {
					s.add(new FloatDataType());

					Structure mys1 = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category5"), "my_s1", 0);
					mys1.add(s);

					mys1 =
						(Structure) dtm.addDataType(mys1, DataTypeConflictHandler.DEFAULT_HANDLER);
					// edit FloatStruct
					fs.add(mys1);

					// edit MyStruct
					ms.add(new FloatDataType());
					ms.add(new WordDataType());

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// conflict on ArrayStruct (6)
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// use ORIGINAL ArrayStruct

		// conflict on MyStruct    (5)
		chooseOption(DataTypeMergeManager.OPTION_MY);// use MY MyStruct

		// conflict on FloatStruct (2)
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete FloatStruct

		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"), "FloatStruct"));

		waitForCompletion();
		Structure fs =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
				"FloatStruct");
		assertNull(fs);

		// MyStruct should have a FloatDataType and a Word
		Structure ms =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "MyStruct");
		DataTypeComponent[] dtcs = ms.getDefinedComponents();
		assertEquals(4, dtcs.length);

		assertTrue(dtcs[2].getDataType().isEquivalent(new FloatDataType()));
		assertTrue(dtcs[3].getDataType().isEquivalent(new WordDataType()));

		// ArrayStruct should have 3 components
		Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		dtcs = a.getDefinedComponents();
		assertEquals(3, dtcs.length);
	}

	@Test
	public void testEditUnions() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					// 2 components should get removed from CoolUnion
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_DLL_Table", s);
					Pointer p = PointerDataType.getPointer(td, 4);
					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(p);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose DLL_Table from ORIGINAL

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		// DLL_Table should exist

		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// AnotherUnion should contain DLL_Table from the Original
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
		assertNotNull(union);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_DLL_Table");
		assertNotNull(td);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(3, dtcs.length);
		assertEquals(dll, dtcs[0].getDataType());
		DataType dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(td, ((Pointer) dt).getDataType());
		assertTrue(dtcs[2].getDataType().isEquivalent(new ByteDataType()));

		union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertEquals("my comments", dtcs[5].getComment());
		assertEquals("Float Field", dtcs[5].getFieldName());

	}

	@Test
	public void testEditUnions2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					// 2 components should get removed from CoolUnion
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		// DLL_Table should not exist

		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

		// AnotherUnion should contain one component since DLL_Table was deleted
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
		assertNotNull(union);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(1, dtcs.length);
		assertTrue(dtcs[0].getDataType().isEquivalent(new ByteDataType()));

		union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		dtcs = union.getComponents();
		assertEquals(4, dtcs.length);
		assertEquals("my comments", dtcs[3].getComment());
		assertEquals("Float Field", dtcs[3].getFieldName());
	}

	@Test
	public void testEditUnions3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		assertEquals(enumm, dtcs[6].getDataType());
		assertEquals(dll, dtcs[3].getDataType());
	}

	@Test
	public void testEditUnions4() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(5, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		assertEquals(enumm, dtcs[4].getDataType());
		assertTrue(dtcs[3].getDataType().isEquivalent(new FloatDataType()));

	}

	@Test
	public void testEditUnions5() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);// my DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete CoolUnion

		waitForCompletion();

		// CoolUnion should be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// enumm should have been added
		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);

		DataTypeComponent[] dtcs = dll.getComponents();
		assertEquals(9, dtcs.length);
		assertTrue(dtcs[8].getDataType().isEquivalent(new WordDataType()));
	}

	@Test
	public void testEditUnions6() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					union.add(td);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		assertEquals(td, dtcs[6].getDataType());
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions7() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					Pointer p = PointerDataType.getPointer(td, 4);// TD_MyEnum *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * * *
					union.add(p);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		for (int i = 0; i < 3; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(td, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions8() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					Pointer p = PointerDataType.getPointer(td, 4);// TD_MyEnum *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * * *

					// create an array of TD_MyEnum * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					dtc = union.add(array);
					dtc.setComment("an array");
					dtc.setFieldName("array field name");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();
		assertTrue(dt instanceof Pointer);

		for (int i = 0; i < 3; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(td, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

}
