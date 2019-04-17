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
package ghidra.app.plugin.core.datamgr;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.*;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import docking.util.KeyBindingUtils;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputWithChoicesDialog;
import docking.widgets.fieldpanel.support.Highlight;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.GTreeNode;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.datamgr.actions.CreateTypeDefDialog;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.function.EditFunctionSignatureDialog;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesPlugin;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProvider;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassFilter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

/**
 * Tests for managing categories through the data manager plugin and tests for
 * actions being enabled when a node is selected.
 */

public class DataTypeManagerPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String BUILTIN_NAME = "BuiltInTypes";
	private static final String PROGRAM_FILENAME = "notepad";

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypeArchiveGTree tree;
	private JTree jTree;
	private ProgramActionContext treeContext;

	private ArchiveNode programNode;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DataTypesProvider provider;

	@Before
	public void setUp() throws Exception {

		removeBinTestDir();

		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		tree = provider.getGTree();
		jTree = (JTree) invokeInstanceMethod("getJTree", tree);
		waitForTree();
		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getRootNode();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);

		treeContext = new DataTypesActionContext(provider, program, tree, null);

		removeDistractingPlugins();
	}

	private void removeDistractingPlugins() {

		// cleanup the display a bit
		ProgramTreePlugin ptp = env.getPlugin(ProgramTreePlugin.class);
		tool.removePlugins(new Plugin[] { ptp });
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(miscPath);
		builder.addDataType(struct);
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(miscPath);
		union.add(new ByteDataType());
		builder.addDataType(union);

		CategoryPath cat1Path = new CategoryPath("/Category1");
		builder.addCategory(cat1Path);
		CategoryPath cat2Path = new CategoryPath(cat1Path, "Category2");
		builder.addCategory(cat2Path);
		CategoryPath cat4Path = new CategoryPath(cat2Path, "Category4");
		builder.addCategory(cat4Path);
		builder.addCategory(new CategoryPath(cat2Path, "Category5"));

		CategoryPath cat3Path = new CategoryPath(cat2Path, "Category3");
		builder.addCategory(cat3Path);
		StructureDataType dt = new StructureDataType("IntStruct", 0);
		dt.add(new WordDataType());
		dt.setCategoryPath(cat3Path);
		builder.addDataType(dt);

		dt = new StructureDataType("CharStruct", 0);
		dt.add(new CharDataType());
		dt.setCategoryPath(cat4Path);
		builder.addDataType(dt);

		StructureDataType dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new WordDataType());
		builder.addDataType(dllTable);

		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "struct_field_names", null);
		myStruct.setCategoryPath(cat2Path);
		builder.addDataType(myStruct);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
		removeBinTestDir();
	}

	@Test
	public void testInvalidArchive() throws Exception {
		final DataTypeManagerHandler managerHandler = plugin.getDataTypeManagerHandler();
		final String[] invalidNames = { "BADARCHIVENAME.gdt" };
		runSwing(() -> invokeInstanceMethod("openArchives", managerHandler,
			new Class[] { String[].class }, new Object[] { invalidNames }));

		GTreeNode rootNode = tree.getRootNode();
		GTreeNode invalidChild = rootNode.getChild("BADARCHIVENAME");
		assertNull("Tree did not close invalid archive.", invalidChild);
	}

	@Test
	public void testCreateCategory() throws Exception {
		// select a category
		GTreeNode miscNode = programNode.getChild("MISC");
		assertNotNull(miscNode);
		expandNode(miscNode);

		int childCount = miscNode.getChildCount();
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "New Category");
		assertTrue(action.isEnabledForContext(treeContext));

		// select "New Category" action
		DataTypeTestUtils.performAction(action, tree, false);

		runSwing(() -> jTree.stopEditing());
		waitForSwing();

		waitForTree();
		SwingUtilities.invokeAndWait(() -> jTree.stopEditing());

		// verify that  the tree opens a new node with the default
		// category name is "New Category"
		assertEquals(childCount + 1, miscNode.getChildCount());
		GTreeNode node = miscNode.getChild("New Category");
		assertNotNull(node);
	}

	@Test
	public void testCreatePointerFromBuiltin() throws Exception {
		//
		// Test that creating a pointer to a built-in type will put that pointer in the program's
		// archive
		//
		disablePointerFilter();// make sure our new type is not filtered out

		ArchiveNode builtInNode = getBuiltInNode();
		expandNode(builtInNode);
		String boolNodeName = "bool";
		GTreeNode boolNode = builtInNode.getChild(boolNodeName);
		assertNotNull(boolNode);
		selectNode(boolNode);

		final DockingActionIf action = getAction(plugin, "Create Pointer");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, true);
		waitForSwing();// the action uses an invokeLater()
		waitForTree();

		final AtomicReference<GTreeNode> selectedNodeReference = new AtomicReference<>();
		runSwing(() -> {
			TreePath selectionPath = tree.getSelectionPath();
			GTreeNode selectedNode = (GTreeNode) selectionPath.getLastPathComponent();
			selectedNodeReference.set(selectedNode);
		});

		GTreeNode selectedNode = selectedNodeReference.get();
		assertNotNull(selectedNode);
		assertEquals(boolNodeName + " *", selectedNode.getName());
	}

	@Test
	public void testCreateTypeDefFromDialog() throws Exception {
		// select a category - this will be the parent category
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Create Typedef From Dialog");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, false);

		//
		// Grab the dialog and set:
		// -the name
		// -the data type
		//
		CreateTypeDefDialog dialog = waitForDialogComponent(CreateTypeDefDialog.class);

		String newTypeDefName = "TestTypeDef";
		JTextField textField = (JTextField) getInstanceField("nameTextField", dialog);
		setText(textField, newTypeDefName);

		final String dataTypeText = "char *";
		final DataTypeSelectionEditor editor =
			(DataTypeSelectionEditor) getInstanceField("dataTypeEditor", dialog);
		runSwing(() -> editor.setCellEditorValueAsText(dataTypeText));

		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);

		waitForTree();
		TreePath[] selectionPaths = tree.getSelectionPaths();
		assertNotNull(selectionPaths);
		assertEquals(1, selectionPaths.length);

		TreePath treePath = selectionPaths[0];
		GTreeNode selectedNode = (GTreeNode) treePath.getLastPathComponent();
		String selectedNodeName = selectedNode.getName();
		assertEquals(newTypeDefName, selectedNodeName);
	}

	@Test
	public void testRenameCategory() throws Exception {
		// select a category
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Rename");
		assertTrue(action.isEnabledForContext(treeContext));

		// select "Rename" action
		final String newCategoryName = "My Misc Category";
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();
		runSwing(() -> {
			int rowForPath = jTree.getRowForPath(miscNode.getTreePath());

			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, miscNode,
				true, true, true, rowForPath);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText(newCategoryName);
			jTree.stopEditing();
		});
		waitForProgram();
		waitForTree();

		// make sure the new node is selected
		TreePath[] selectionPaths = tree.getSelectionPaths();
		assertNotNull(selectionPaths);
		assertEquals(1, selectionPaths.length);

		CategoryNode newMiscNode = (CategoryNode) programNode.getChild(newCategoryName);
		GTreeNode selectedNode = (GTreeNode) selectionPaths[0].getLastPathComponent();
		assertEquals(newMiscNode, selectedNode);

		assertEquals("My Misc Category", newMiscNode.getName());
		Category c = getRootCategory().getCategory(newCategoryName);
		assertNotNull(c);
		assertEquals(newMiscNode.getCategory(), c);
		assertNull(programNode.getChild(miscNodeName));

		// undo
		undo();

		assertNotNull(programNode.getChild(miscNodeName));
		assertNull(programNode.getChild(newCategoryName));

		// redo
		redo();

		assertNull(programNode.getChild(miscNodeName));
		assertNotNull(programNode.getChild(newCategoryName));
	}

	@Test
	public void testRenameCategoryDuplicate() throws Exception {
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Rename");
		assertTrue(action.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();
		SwingUtilities.invokeLater(() -> {
			TreePath editingPath = jTree.getEditingPath();
			GTreeNode editingNode = (GTreeNode) editingPath.getLastPathComponent();
			int rowForPath = jTree.getRowForPath(editingPath);

			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree,
				editingNode, true, true, true, rowForPath);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("Category1");
			jTree.stopEditing();
		});

		final OptionDialog d = waitForDialogComponent(OptionDialog.class);
		runSwing(() -> d.close());
		waitForSwing();

		assertTrue(!jTree.isEditing());
	}

	@Test
	public void testCopyCategory2DataType() throws Exception {
		// not allowed in the same data type manager
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode cat5Node = cat2Node.getChild("Category5");
		expandNode(cat5Node);
		selectNode(cat5Node);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));

		GTreeNode miscNode = programNode.getChild("MISC");
		expandNode(miscNode);
		DataTypeNode unionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");
		selectNode(unionNode);

		pasteAction = getAction(plugin, "Paste");
		assertTrue(!pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testDeleteCategoryInProgram() throws Exception {
		// delete category from the Program
		// delete Category4
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		CategoryNode cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode cat4Node = cat2Node.getChild("Category4");
		selectNode(cat4Node);

		final DockingActionIf action = getAction(plugin, "Delete");
		assertTrue(action.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(action, tree, false);

		// hit the Yes button the dialog
		pressButtonOnOptionDialog("Yes");

		// must again retrieve the nodes after a delete, as the old nodes are disposed
		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat2Node.getChild("Category4"));
		ArrayList<DataType> list = new ArrayList<>();
		Archive archive = cat2Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());

		undo();

		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNotNull(cat2Node.getChild("Category4"));

		redo();

		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat2Node.getChild("Category4"));
	}

	@Test
	public void testDeleteCategoryInProgram2() throws Exception {
		// delete category from the Program
		// delete Category2 from Category1
		CategoryNode cat1Node = (CategoryNode) programNode.getChild("Category1");
		expandNode(cat1Node);

		CategoryNode cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		selectNode(cat2Node);

		final DockingActionIf action = getAction(plugin, "Delete");
		assertTrue(action.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(action, tree, false);
		waitForSwing();

		// hit the Yes button the dialog
		pressButtonOnOptionDialog("Yes");

		// must again retrieve the nodes after a delete, as the old nodes are disposed
		cat1Node = (CategoryNode) programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat1Node.getChild("Category2"));
		ArrayList<DataType> list = new ArrayList<>();
		Archive archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());
		archive.getDataTypeManager().findDataTypes("IntStruct", list);

		undo();

		cat1Node = (CategoryNode) programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNotNull(cat2Node);
		list = new ArrayList<>();
		archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(1, list.size());
		list.clear();
		archive.getDataTypeManager().findDataTypes("IntStruct", list);
		assertEquals(1, list.size());

		redo();

		cat1Node = (CategoryNode) programNode.getChild("Category1");
		assertNull(cat1Node.getChild("Category2"));
		list = new ArrayList<>();
		archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());
		archive.getDataTypeManager().findDataTypes("IntStruct", list);
	}

	@Test
	public void testBuiltInCategoryForDataTypes() throws Exception {
		// verify that you cannot cut/paste data types to built in types category
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		DataTypeNode myStructNode = (DataTypeNode) cat2Node.getChild("MyStruct");

		GTreeNode rootNode = tree.getRootNode();
		GTreeNode builtInNode = rootNode.getChild("BuiltInTypes");

		selectNode(myStructNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		cutAction = getAction(plugin, "Cut");
		pasteAction = getAction(plugin, "Paste");

		assertTrue(cutAction.isEnabledForContext(treeContext));
		assertTrue(copyAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(cutAction, tree, false);

		selectNode(builtInNode);
		assertTrue(!pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testBuiltInCategoryForCategories() throws Exception {
		// verify that you cannot cut/paste other categories to the built in types category
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode rootNode = tree.getRootNode();
		GTreeNode builtInNode = rootNode.getChild("BuiltInTypes");

		selectNode(cat2Node);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		cutAction = getAction(plugin, "Cut");
		pasteAction = getAction(plugin, "Paste");

		assertTrue(cutAction.isEnabledForContext(treeContext));
		assertTrue(copyAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(cutAction, tree);

		selectNode(builtInNode);
		assertTrue(!pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testCloseProgram() throws Exception {

		SwingUtilities.invokeAndWait(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});
		GTreeNode rootNode = tree.getRootNode();
		assertEquals(1, rootNode.getChildCount());
	}

	@Test
	public void testExpandAll() throws Exception {

		GTreeNode rootNode = tree.getRootNode();
		selectNode(rootNode);
		DockingActionIf expandAction = getAction(plugin, "Expand All");
		assertTrue(expandAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(expandAction, tree);

		waitForTree();

		//verify all nodes are expanded
		checkNodesExpanded(rootNode);
	}

	@Test
	public void testDetailedSearch() throws Exception {
		toggleDetailedSearch(false);
		filterTree("struct_field_name");
		assertEmptyTree();

		toggleDetailedSearch(true);
		assertSingleFilterMatch(
			new String[] { "Data Types", "notepad", "Category1", "Category2", "MyStruct" });
	}

	@Test
	public void testCollapseAll() throws Exception {

		GTreeNode rootNode = tree.getRootNode();
		selectNode(rootNode);
		DockingActionIf collapseAction = getAction(plugin, "Collapse All");
		assertTrue(collapseAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(collapseAction, tree);

		//verify all nodes are collapsed
		checkNodesCollapsed(rootNode);
	}

	@Test
	public void testSaveRestoreFilterStates() throws Exception {
		final ToggleDockingActionIf arraysAction =
			(ToggleDockingActionIf) getAction(plugin, "Filter Arrays");
		assertTrue(arraysAction.isSelected());
		arraysAction.setSelected(false);
		DataTypeTestUtils.performAction(arraysAction, tree);

		// state is off
		final ToggleDockingActionIf pointerAction =
			(ToggleDockingActionIf) getAction(plugin, "Filter Pointers");
		assertTrue(pointerAction.isSelected());

		pointerAction.setSelected(false);
		DataTypeTestUtils.performAction(pointerAction, tree, false);

		// state is off
		env.saveRestoreToolState();
		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		ToggleDockingActionIf action = (ToggleDockingActionIf) getAction(plugin, "Filter Arrays");
		assertTrue(!action.isSelected());
		action = (ToggleDockingActionIf) getAction(plugin, "Filter Pointers");
		assertTrue(!action.isSelected());
	}

	@Test
	public void testRefreshBuiltins() throws Exception {
		GTreeNode treeRoot = tree.getRootNode();
		GTreeNode builtInNode = treeRoot.getChild("BuiltInTypes");
		if (builtInNode.getChild("TestDataType") != null) {
			Assert.fail("Test setup Error: ghidra.app.test.TestDataType was not removed!");
		}

		compileJavaFile();

		DockingActionIf action = getAction(plugin, "Refresh BuiltInTypes");
		assertTrue(action.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(action, tree, false);

		waitForTasks();

		waitForProgram();

		waitForActionToBeEnabled(action);

		builtInNode = treeRoot.getChild("BuiltInTypes");
		assertNotNull(builtInNode.getChild("TestDataType"));

		ClassFilter filter = new BuiltInDataTypeClassExclusionFilter();
		ArrayList<DataType> listOne =
			new ArrayList<>(ClassSearcher.getInstances(BuiltInDataType.class, filter));

		DataTypeManager bdtm = plugin.getBuiltInDataTypesManager();
		ArrayList<DataType> listTwo = new ArrayList<>();
		Iterator<DataType> iter = bdtm.getAllDataTypes();
		while (iter.hasNext()) {
			DataType dt = iter.next();
			listTwo.add(dt);
		}
		for (int i = 0; i < listOne.size(); i++) {
			DataType dt = listOne.get(i);
			boolean found = false;
			for (int j = 0; j < listTwo.size(); j++) {
				DataType dt2 = listTwo.get(j);
				if (dt.isEquivalent(dt2)) {
					found = true;
					break;
				}
			}
			assertTrue(found);
		}
	}

	@Test
	public void testDataTypePreviewCopyHtmlText() throws Exception {

		openPreview();

		GTreeNode bNode = programNode.getChild("DLL_Table");
		assertNotNull(bNode);
		selectNode(bNode);

		String previewText = getPreviewText();
		assertThat(previewText, startsWith("<html>"));

		selectEntirePreview();

		boolean actionFired = copyPreviewViaKeyMapping();
		assertTrue(actionFired);
	}

	@Test
	public void testEditFunctionDefintionDataType() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "int Bob(long aaa, ...)");
		fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "aaa");
		assertParamType(fun, 0, new LongDataType());
		assertEquals(IntegerDataType.class, fun.getReturnType().getClass());
		assertTrue(fun.hasVarArgs());
	}

	@Test
	public void testEditFunctionDefintionName() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "undefined Tom(byte Joe)");
		DataType dt = program.getDataTypeManager().getDataType("/Bob");
		assertNull(dt);
		fun = getFunctionDefinition("Tom");
		assertNotNull(fun);
	}

	@Test
	public void testEditFunctionDefintionDataTypeParamNameOnly() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "undefined Bob(byte Tom)");
		fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Tom");
	}

	@Test
	public void testEditingFunctionDefinitionWithNullParamName() {
		createFunctionDefinition("Bob", (String) null);
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertEquals("", fun.getArguments()[0].getName());
	}

	@Test
	public void testEditingFunctionDefinitionWithVariousParameterNames() {
		createFunctionDefinition("Bob", (String) null, "", "Tom");
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertEquals("", fun.getArguments()[0].getName());
		assertEquals("", fun.getArguments()[1].getName());
		assertEquals("Tom", fun.getArguments()[2].getName());
	}

	//==================================================================================================
	// Private methods
	//==================================================================================================
	private void editSignature(String name, String newSignature) {
		expandNode(programNode);
		GTreeNode child = programNode.getChild(name);
		selectNode(child);
		final DockingActionIf action = getAction(plugin, "Edit");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, false);

		EditFunctionSignatureDialog dialog =
			waitForDialogComponent(EditFunctionSignatureDialog.class);

		JTextField textField = (JTextField) getInstanceField("signatureField", dialog);
		setText(textField, newSignature);
		pressButtonByText(dialog, "OK");

	}

	private void assertParamName(FunctionDefinition fun, int index, String name) {
		ParameterDefinition param = fun.getArguments()[index];
		assertEquals(name, param.getName());
	}

	private void assertParamType(FunctionDefinition fun, int index, DataType dt) {
		ParameterDefinition param = fun.getArguments()[index];
		assertEquals(dt.getClass(), param.getDataType().getClass());
	}

	private FunctionDefinition getFunctionDefinition(String name) {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType("/" + name);
		assertTrue(dataType instanceof FunctionDefinition);
		return (FunctionDefinition) dataType;
	}

	private void createFunctionDefinition(String functionName, String... paramNames) {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		int id = dataTypeManager.startTransaction("test");
		FunctionDefinitionDataType dt = new FunctionDefinitionDataType(functionName);
		ParameterDefinition[] args = new ParameterDefinition[paramNames.length];
		for (int i = 0; i < paramNames.length; i++) {
			args[i] = new ParameterDefinitionImpl(paramNames[i], new ByteDataType(), null);
		}
		dt.setArguments(args);
		dataTypeManager.addDataType(dt, null);
		dataTypeManager.endTransaction(id, true);
	}

	private void selectEntirePreview() {
		runSwing(() -> {
			JTextPane pane = provider.getPreviewPane();
			// note: the selectAll only works when the caret selection is visible (this normally
			//       happens when the component has focus)
			pane.getCaret().setSelectionVisible(true);
			pane.selectAll();
		});
		waitForSwing();
	}

	private boolean copyPreviewViaKeyMapping() throws Exception {

		KeyStroke controlC =
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
		JTextPane previewPane = provider.getPreviewPane();
		Action defaultAction =
			KeyBindingUtils.getAction(previewPane, controlC, JComponent.WHEN_FOCUSED);

		SpyAction spyAction = new SpyAction(defaultAction);

		KeyBindingUtils.registerAction(previewPane, controlC, spyAction, JComponent.WHEN_FOCUSED);

		triggerKey(previewPane, DockingUtils.CONTROL_KEY_MODIFIER_MASK, KeyEvent.VK_C, 'c');
		waitForSwing();

		return spyAction.actionFired();
	}

	private String getPreviewText() {
		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> ref.set(provider.getPreviewText()));
		return ref.get();
	}

	private void openPreview() {
		runSwing(() -> provider.setPreviewWindowVisible(true));
	}

	private ArchiveNode getBuiltInNode() {
		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getRootNode();
		ArchiveNode builtinNode = (ArchiveNode) archiveRootNode.getChild(BUILTIN_NAME);
		assertNotNull(builtinNode);
		return builtinNode;
	}

	private void findReferencesToField(String choice) {
		DockingActionIf searchAction = getAction(plugin, "Find Uses of Field");
		assertTrue(searchAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(searchAction, tree, false);

		InputWithChoicesDialog d = waitForDialogComponent(InputWithChoicesDialog.class);
		@SuppressWarnings("unchecked")
		GhidraComboBox<String> combo = (GhidraComboBox<String>) getInstanceField("combo", d);
		setComboBoxSelection(combo, choice);
		pressButtonByText(d, "OK");

		waitForSearchResults();
	}

	@SuppressWarnings("unchecked")
	private LocationReferencesProvider getLocationReferencesProvider() {
		LocationReferencesPlugin locationRefsPlugin =
			getPlugin(tool, LocationReferencesPlugin.class);

		List<LocationReferencesProvider> providerList =
			(List<LocationReferencesProvider>) getInstanceField("providerList", locationRefsPlugin);
		if (providerList.size() == 0) {
			return null;
		}
		return providerList.get(0);
	}

	private ThreadedTableModel<?, ?> getTableModel() {

		waitForCondition(() -> getLocationReferencesProvider() != null);

		LocationReferencesProvider refsProvider = getLocationReferencesProvider();
		Object referencesPanel = getInstanceField("referencesPanel", refsProvider);
		return (ThreadedTableModel<?, ?>) getInstanceField("tableModel", referencesPanel);
	}

	private void waitForSearchResults() {
		ThreadedTableModel<?, ?> model = getTableModel();
		waitForTableModel(model);
	}

	private HighlightProvider getHighlightProvider() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		FormatManager fm = (FormatManager) getInstanceField("formatMgr", service);
		return (HighlightProvider) getInstanceField("highlightProvider", fm);
	}

	private void assertOperandHighlight(String rep, Address addr) {
		assertHighlight(OperandFieldFactory.class, rep, addr);
	}

	private void assertFieldNameHighlight(String rep, Address addr) {
		assertHighlight(FieldNameFieldFactory.class, rep, addr);
	}

	private void assertHighlight(Class<? extends FieldFactory> clazz, String rep, Address addr) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(addr);
		if (cu instanceof Data) {
			Data data = (Data) cu;
			Address minAddress = data.getMinAddress();
			long offset = addr.subtract(minAddress);
			if (offset != 0) {
				Data subData = data.getComponentAt((int) offset);
				cu = subData;
			}
		}
		HighlightProvider highlighter = getHighlightProvider();
		Highlight[] highlights = highlighter.getHighlights(rep, cu, clazz, -1);
		assertNotNull(highlights);
		assertTrue(highlights.length != 0);
	}

	private Address addr(long offset) {
		AddressFactory addrMap = program.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private void assertSingleFilterMatch(String[] path) {
		GTreeNode rootNode = tree.getRootNode();

		GTreeNode node = rootNode;
		for (int i = 0; i < path.length; i++) {
			String nodeName = path[i];
			assertEquals(node.getName(), nodeName);

			final GTreeNode finalNode = node;
			final GTreeNode[] childBox = new GTreeNode[1];
			runSwing(() -> {
				int childCount = finalNode.getChildCount();
				if (childCount == 1) {
					childBox[0] = finalNode.getChild(0);
				}
			});

			if (i + 1 < path.length) {
				String expectedChild = path[i + 1];
				assertNotNull("Parent '" + node.getName() + "' did not have child " + expectedChild,
					childBox[0]);
				node = childBox[0];
			}
		}
	}

	private void assertEmptyTree() {
		final GTreeNode rootNode = tree.getRootNode();
		final Integer[] box = new Integer[1];
		runSwing(() -> box[0] = rootNode.getChildCount());
		assertEquals("Root node is not empty as expected", 0, (int) box[0]);
	}

	private void filterTree(String text) {
		tree.setFilterText(text);
		waitForTree();
	}

	private void toggleDetailedSearch(final boolean enable) {
		final DockingActionIf includeDataMembersAction =
			getAction(plugin, "Include Data Members in Filter");
		runSwing(() -> {
			ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) includeDataMembersAction;
			toggleAction.setSelected(enable);
		});
		waitForTree();
	}

	private void disablePointerFilter() {
		DockingActionIf filterPointersAction = getAction(plugin, "Filter Pointers");
		ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) filterPointersAction;
		setToggleActionSelected(toggleAction, treeContext, false);
		waitForTree();
	}

	private void waitForActionToBeEnabled(DockingActionIf action) {
		int numWaits = 0;
		while (!action.isEnabled() && ++numWaits < 50) {
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				// don't care; will try again
			}
		}
	}

	private void undo() throws Exception {
		runSwing(() -> {
			try {
				program.undo();
				program.flushEvents();
			}
			catch (Exception e) {
				failWithException("Exception performing undo", e);
			}
		});
		waitForTasks();
		waitForTree();
	}

	private void redo() throws Exception {
		runSwing(() -> {
			try {
				program.redo();
				program.flushEvents();
			}
			catch (Exception e) {
				failWithException("Exception performing undo", e);
			}
		});
		waitForTasks();
		waitForTree();
	}

	private void pressButtonOnOptionDialog(String buttonName) throws Exception {
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		JButton button = findButtonByText(d, buttonName);
		assertNotNull(button);
		runSwing(() -> button.doClick());
		waitForProgram();
	}

	private void waitForProgram() throws Exception {
		program.flushEvents();
		waitForTasks();
	}

	private Category getRootCategory() {
		return program.getListing().getDataTypeManager().getRootCategory();
	}

	private void checkNodesExpanded(GTreeNode parent) {
		assertTrue(tree.isExpanded(parent.getTreePath()));

		int nchild = parent.getChildCount();
		for (int i = 0; i < nchild; i++) {
			GTreeNode node = parent.getChild(i);
			if (node.getChildCount() > 0) {
				checkNodesExpanded(node);
			}
		}
	}

	private void checkNodesCollapsed(GTreeNode parent) {
		if (parent != tree.getRootNode()) {
			assertTrue(!tree.isExpanded(parent.getTreePath()));
		}

		int nchild = parent.getChildCount();
		for (int i = 0; i < nchild; i++) {
			GTreeNode node = parent.getChild(i);
			if (node.getChildCount() > 0) {
				checkNodesCollapsed(node);
			}
		}
	}

	private File getBinTestDir() throws FileNotFoundException {
		File file = getTestDataTypeFile();
		if (file == null) {
			throw new FileNotFoundException("Could not find resource TestDataType.txt");
		}
		File parent = file.getParentFile();
		String parentPath = parent.getAbsolutePath();
		int pos = parentPath.lastIndexOf("ghidra");
		String destPath = parentPath.substring(0, pos - 1);
		String newpath =
			destPath + File.separator + "ghidra" + File.separator + "app" + File.separator + "test";
		return new File(newpath);
	}

	private void removeBinTestDir() {
		try {
			File binDir = getBinTestDir();
			Msg.debug(this, "DT bin test dir: " + binDir);
			if (binDir.isDirectory()) {
				Msg.debug(this, "\tdeleting the bin dir...");
				boolean success = FileUtilities.deleteDir(binDir);
				Msg.debug(this, "\tsuccess?: " + success);
			}
			else {
				Msg.debug(this, "NOT a directory - not deleting!");
			}
		}
		catch (FileNotFoundException e) {
			System.err.println("Unable to delete test dir?: " + e.getMessage());
		}
	}

	private void compileJavaFile() throws Exception {

		boolean success = false;
		try {
			File file = getTestDataTypeFile();
			File binDir = getBinTestDir();
			if (!binDir.exists()) {
				if (!binDir.mkdir()) {
					Assert.fail("Could not create directory " + binDir.getAbsolutePath());
				}
			}

			File javaFile = new File(binDir, "TestDataType.java");

			FileUtilities.copyFile(file, javaFile, false, TaskMonitorAdapter.DUMMY_MONITOR);
			assertTrue(javaFile.exists());

			JavaCompiler j = new JavaCompiler();
			j.compile(javaFile);
			success = true;
		}
		finally {
			if (!success) {
				removeBinTestDir();
			}
		}
	}

	private File getTestDataTypeFile() {
		URL url = getClass().getResource("TestDataType.txt");
		try {
			URI uri = new URI(url.toExternalForm());
			return new File(uri);
		}
		catch (URISyntaxException e) {
			throw new RuntimeException("Cannot find TestDataType.txt");
		}

	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNode(GTreeNode node) {
		tree.setSelectedNode(node);
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private class SpyAction extends AbstractAction {

		private Action defaultAction;
		private AtomicBoolean actionFired = new AtomicBoolean();

		public SpyAction(Action defaultAction) {
			this.defaultAction = defaultAction;
		}

		boolean actionFired() {
			return actionFired.get();
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			defaultAction.actionPerformed(e);
			actionFired.set(true);
		}

	}

}
