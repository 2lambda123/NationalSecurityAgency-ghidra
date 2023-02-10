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
package ghidra.framework.main;

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.net.ApplicationKeyManagerUtils;
import ghidra.util.HelpLocation;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;

/**
 * Helper class to manage the actions on the Edit menu.
 */
class EditActionManager {
	/**
	 * PKCS Private Key/Certificate File Filter
	 */
	public static final GhidraFileFilter CERTIFICATE_FILE_FILTER =
		new ExtensionFileFilter(ApplicationKeyManagerUtils.PKCS_FILE_EXTENSIONS, "PKCS Key File");

	private FrontEndPlugin plugin;
	private FrontEndTool tool;
	private DockingAction editPluginPathAction;
	private DockingAction editCertPathAction;
	private DockingAction clearCertPathAction;

	EditActionManager(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = (FrontEndTool) plugin.getTool();
		createActions();
	}

	/**
	 * Create the menu items.
	 */
	private void createActions() {

		// window.addSeparator(Ghidra.MENU_FILE);

		editPluginPathAction = new DockingAction("Edit Plugin Path", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				editPluginPath();
			}
		};
// ACTIONS - auto generated
		editPluginPathAction.setEnabled(true);

		editPluginPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Plugin Path..." }, "GEdit"));

		editCertPathAction = new DockingAction("Set PKI Certificate", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				editCertPath();
			}
		};
// ACTIONS - auto generated
		editCertPathAction.setEnabled(true);

		editCertPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Set PKI Certificate..." }, "PKI"));

		clearCertPathAction = new DockingAction("Clear PKI Certificate", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clearCertPath();
			}
		};
// ACTIONS - auto generated
		clearCertPathAction.setEnabled(ApplicationKeyManagerFactory.getKeyStore() != null);

		clearCertPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Clear PKI Certificate..." }, "PKI"));

		clearCertPathAction.setHelpLocation(new HelpLocation("FrontEndPlugin",
			"Set_PKI_Certificate"));
		tool.addAction(editCertPathAction);
		tool.addAction(clearCertPathAction);
		tool.addAction(editPluginPathAction);
	}

	/**
	 * Pop up the edit plugin path dialog.
	 */
	private void editPluginPath() {
		EditPluginPathDialog pluginPathDialog = new EditPluginPathDialog();
		pluginPathDialog.show(tool);
	}

	private void clearCertPath() {

		String path = ApplicationKeyManagerFactory.getKeyStore();
		if (path == null) {
			// unexpected
			clearCertPathAction.setEnabled(false);
			return;
		}

		if (OptionDialog.YES_OPTION != OptionDialog.showYesNoDialog(tool.getToolFrame(),
			"Clear PKI Certificate", "Clear PKI certificate setting?\n(" + path + ")")) {
			return;
		}

		ApplicationKeyManagerFactory.setKeyStore(null, true);
		clearCertPathAction.setEnabled(false);
	}

	private void editCertPath() {

		GhidraFileChooser certFileChooser = createCertFileChooser();

		File dir = null;
		File oldFile = null;
		String path = ApplicationKeyManagerFactory.getKeyStore();
		if (path != null) {
			oldFile = new File(path);
			dir = oldFile.getParentFile();
			if (!oldFile.isFile()) {
				oldFile = null;
				if (!dir.isDirectory()) {
					dir = null;
				}
			}
		}
		if (dir == null) {
			dir = new File(System.getProperty("user.home"));
		}

		if (oldFile != null) {
			certFileChooser.setSelectedFile(oldFile);
		}
		else {
			certFileChooser.setCurrentDirectory(dir);
		}

		boolean validInput = false;
		while (!validInput) {
			// display the file chooser and handle the action, Select or Create
			File file = certFileChooser.getSelectedFile();
			if (file == null) {
				return; // cancelled
			}
			ApplicationKeyManagerFactory.setKeyStore(file.getAbsolutePath(), true);
			clearCertPathAction.setEnabled(true);
			validInput = true;
		}

		certFileChooser.dispose();
	}

	private GhidraFileChooser createCertFileChooser() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getToolFrame());
		fileChooser.setTitle("Select Certificate (req'd for PKI authentication only)");
		fileChooser.setApproveButtonText("Set Certificate");
		fileChooser.setFileFilter(CERTIFICATE_FILE_FILTER);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		fileChooser.setHelpLocation(new HelpLocation(plugin.getName(), "Set_PKI_Certificate"));
		return fileChooser;
	}
}
