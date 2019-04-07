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
package help.screenshot;

import java.io.*;
import java.util.*;

import javax.swing.*;

import org.junit.Test;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.pathmanager.PathManager;
import docking.widgets.tree.*;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.plugin.core.console.ConsoleComponentProvider;
import ghidra.app.plugin.core.script.*;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.ConsoleService;
import ghidra.util.HelpLocation;

public class GhidraScriptMgrPluginScreenShots extends GhidraScreenShotGenerator {

	public GhidraScriptMgrPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
	}

	@Test
	public void testNew_Script_Editor() throws Exception {

		performAction("New", "GhidraScriptMgrPlugin", false);

		JDialog d = waitForJDialog(null, "New Script: Type", 5000);
		pressButtonByText(d, "OK");

		d = waitForJDialog(null, "New Script", 5000);
		pressButtonByText(d, "OK");

		captureIsolatedProvider(GhidraScriptEditorComponentProvider.class, 597, 600);
	}

	@Test
	public void testSaveAs() throws Exception {

		final ResourceFile scriptFile = createHelloWorldScript("HelloWorldScript");
		final GhidraScriptComponentProvider provider =
			showProvider(GhidraScriptComponentProvider.class);
		runSwing(() -> {

			HelpLocation helpLocation = new HelpLocation("", "");
			List<ResourceFile> scriptDirs = new ArrayList<>();
			scriptDirs.add(new ResourceFile("/User/home/ghidra_scripts"));

			SaveDialog dialog = new SaveDialog(tool.getToolFrame(), "Save Script", provider,
				scriptDirs, scriptFile, helpLocation);

			tool.showDialog(dialog);
		}, false);

		SaveDialog dialog = waitForDialogComponent(SaveDialog.class);
		captureDialog(dialog);
	}

	@Test
	public void testAssign_Key_Binding() throws Exception {

		ComponentProvider componentProvider = showProvider(GhidraScriptComponentProvider.class);
		JComponent component = componentProvider.getComponent();
		DraggableScriptTable scriptTable =
			(DraggableScriptTable) findComponentByName(component, "SCRIPT_TABLE");
		selectRow(scriptTable, "HelloWorldScript.java");

		performAction("Key Binding", "GhidraScriptMgrPlugin", false);
		captureDialog();
	}

	@Test
	public void testSelect_Font() throws Exception {

		ComponentProvider componentProvider = showProvider(GhidraScriptComponentProvider.class);
		JComponent component = componentProvider.getComponent();
		DraggableScriptTable scriptTable =
			(DraggableScriptTable) findComponentByName(component, "SCRIPT_TABLE");

		selectRow(scriptTable, "HelloWorldScript.java");
		performAction("Edit", "GhidraScriptMgrPlugin", false);

		performAction("Select Font", "GhidraScriptMgrPlugin", false);
		captureDialog();
	}

	@Test
	public void testScript_Dirs() throws Exception {
		List<Path> paths = new ArrayList<>();
		paths.add(new Path("$USER_HOME/ghidra_scripts"));
		paths.add(new Path("$GHIDRA_HOME/Features/Base/ghidra_scripts"));
		paths.add(new Path("/User/defined/invalid/directory"));

		ComponentProvider provider = showProvider(GhidraScriptComponentProvider.class);
		PathManager pathManager = (PathManager) getInstanceField("pathManager", provider);
		pathManager.setPaths(paths);
		final PickPathsDialog pathsDialog = new PickPathsDialog(null, pathManager);
		runSwing(() -> DockingWindowManager.showDialog(null, pathsDialog), false);

		PickPathsDialog dialog = waitForDialogComponent(PickPathsDialog.class);
		captureDialog(dialog);
	}

	@Test
	public void testEdit_Script() throws Exception {

		ResourceFile newScript = createHelloWorldScript("MyHelloWorldScript");
		ComponentProvider componentProvider = showProvider(GhidraScriptComponentProvider.class);

		JComponent component = componentProvider.getComponent();
		DraggableScriptTable scriptTable =
			(DraggableScriptTable) findComponentByName(component, "SCRIPT_TABLE");
		selectRow(scriptTable, newScript.getName());
		performAction("Edit", "GhidraScriptMgrPlugin", false);

		waitForSwing();

		GhidraScriptEditorComponentProvider provider =
			getProvider(GhidraScriptEditorComponentProvider.class);

		moveProviderToFront(provider, 557, 378);
		captureProvider(provider);
	}

	@Test
	public void testScript_Manager() {
		ComponentProvider scriptManager = showProvider(GhidraScriptComponentProvider.class);
		JComponent component = scriptManager.getComponent();
		final JSplitPane splitPane =
			(JSplitPane) findComponentByName(component, "dataDescriptionSplit");
		runSwing(() -> splitPane.setDividerLocation(0.63));

		DraggableScriptTable scriptTable =
			(DraggableScriptTable) findComponentByName(component, "SCRIPT_TABLE");

		GTree scriptCategoryTree = (GTree) findComponentByName(component, "CATEGORY_TREE");
		removeSuspectNodes(scriptCategoryTree);

		selectPath(scriptCategoryTree, "Scripts", "Examples");
		collapse(scriptCategoryTree, "Examples");// don't open examples (silly JTree)

		selectRow(scriptTable, "HelloWorldScript.java");
		scriptTable.scrollToSelectedRow();

		moveProviderToFront(scriptManager, 1333, 570);
		captureProvider(scriptManager);
	}

	@Test
	public void testConsole() throws Exception {
		ConsoleService service = tool.getService(ConsoleService.class);

		//@formatter:off
		service.addErrorMessage("",
			"/User/home/ghidra_scripts/HellowWorldScript1.java:29: ';' expected\n"+
				"\t}\n"+
				"\t^\n"+
				"1 error\n" +
				"> Unable to compile script class: HellowWorldScript1.java\n");
		//@formatter:on

		ConsoleComponentProvider provider = showProvider(ConsoleComponentProvider.class);
		moveProviderToFront(provider, 700, 225);
		captureProvider(provider);
	}

	@Test
	public void testDelete_Script_Confirm() throws Exception {
		createHelloWorldScript("FooScript");

		ComponentProvider componentProvider = showProvider(GhidraScriptComponentProvider.class);
		JComponent component = componentProvider.getComponent();
		DraggableScriptTable scriptTable =
			(DraggableScriptTable) findComponentByName(component, "SCRIPT_TABLE");
		selectRow(scriptTable, "FooScript.java");
		performAction("Delete", "GhidraScriptMgrPlugin", false);
		captureDialog();
	}

	@Test
	public void testRename() throws Exception {

		final ResourceFile scriptFile = createHelloWorldScript("HelloWorldScript");
		final GhidraScriptComponentProvider provider =
			showProvider(GhidraScriptComponentProvider.class);

		runSwing(() -> {

			HelpLocation helpLocation = new HelpLocation("", "");
			List<ResourceFile> scriptDirs = new ArrayList<>();
			scriptDirs.add(new ResourceFile("/User/home/ghidra_scripts"));

			SaveDialog dialog = new SaveDialog(tool.getToolFrame(), "Rename Script", provider,
				scriptDirs, scriptFile, helpLocation);

			tool.showDialog(dialog);
		}, false);

		SaveDialog dialog = waitForDialogComponent(SaveDialog.class);
		captureDialog(dialog);
	}

	@Test
	public void testPick() {

		List<String> items = new ArrayList<>();
		items.add("Java");
		items.add("Python");
		final PickProviderDialog pickDialog = new PickProviderDialog(items, "Java");
		runSwing(() -> tool.showDialog(pickDialog), false);

		PickProviderDialog dialog = waitForDialogComponent(PickProviderDialog.class);
		captureDialog(dialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void collapse(final GTree tree, final String nodeName) {
		runSwing(() -> {
			GTreeRootNode rootNode = tree.getRootNode();
			GTreeNode exmaplesNode = rootNode.getChild(nodeName);
			tree.collapseAll(exmaplesNode);
		});
	}

	private void removeSuspectNodes(final GTree scriptCategoryTree) {
		List<String> accepted = new ArrayList<>(
			Arrays.asList("Examples", "Data Types", "Binary", "Functions", "Import", "Analysis"));

		List<GTreeNode> toRemove = new ArrayList<>();
		final GTreeRootNode rootNode = scriptCategoryTree.getRootNode();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode child : children) {
			String name = child.getName();
			if (!accepted.contains(name)) {
				toRemove.add(child);
			}
		}

		for (GTreeNode node : toRemove) {
			rootNode.removeNode(node);
		}

		waitForTree(scriptCategoryTree);
	}

	private ResourceFile createTempScriptFile(String name) {
		File userScriptsDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);

		if (name.length() > 50) {
			// too long and the script manager complains
			name = name.substring(name.length() - 50);
		}

		File tempFile = new File(userScriptsDir + File.separator + name + ".java");
		tempFile.deleteOnExit();
		return new ResourceFile(tempFile);
	}

	private void writeStringToFile(ResourceFile file, String string) throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(file.getFile(false)));
		writer.write(string);
		writer.close();
	}

	private ResourceFile createHelloWorldScript(String name) throws Exception {
		ResourceFile newScriptFile = createTempScriptFile(name);
		String filename = newScriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String newScript = "//Writes \"Hello World\" to console.\n" +
				"//@category    Examples.Test\n" +
				"//@menupath    Help.Examples.Hello World\n" +
				"//@keybinding  ctrl shift COMMA\n" +
				"//@toolbar     world.png\n\n" +
				"import ghidra.app.script.GhidraScript;\n\n" +
				"public class "+className+" extends GhidraScript {\n" +

				"	@Override\n" +
				"	public void run() throws Exception {\n" +
				"		println(\"Hello World\");\n" +
				"	}\n" +
				"}\n";

		//@formatter:on

		writeStringToFile(newScriptFile, newScript);

		return newScriptFile;
	}
}
