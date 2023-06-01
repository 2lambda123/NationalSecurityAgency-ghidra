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
package ghidra.app.plugin.core.decompile.actions;

import java.io.*;

import javax.swing.Icon;

import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GIcon;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.symbol.IllegalCharCppTransformer;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

public class ExportToCAction extends AbstractDecompilerAction {
	private static final Icon EXPORT_ICON = new GIcon("icon.decompiler.action.export");
	private static final String LAST_USED_C_FILE = "last.used.decompiler.c.export.file";

	public ExportToCAction() {
		super("Export to C");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarExport"));
		setToolBarData(new ToolBarData(EXPORT_ICON, "Local"));
		setDescription("Export the current function to C");
	}

	private File readLastUsedFile() {
		String filename = Preferences.getProperty(LAST_USED_C_FILE);
		if (filename == null) {
			return null;
		}
		return new File(filename);
	}

	private void saveLastUsedFileFile(File file) {
		Preferences.setProperty(LAST_USED_C_FILE, file.getAbsolutePath());
		Preferences.store();
	}

	private File getFile(DecompilerPanel decompilerPanel) {
		File lastUsedFile = readLastUsedFile();

		String[] extensions = new String[] { "h", "c", "cpp" };
		GhidraFileChooser fileChooser = new GhidraFileChooser(decompilerPanel);
		fileChooser.setFileFilter(new ExtensionFileFilter(extensions, "C/C++ Files"));
		if (lastUsedFile != null) {
			fileChooser.setSelectedFile(lastUsedFile);
		}
		File file = fileChooser.getSelectedFile();
		fileChooser.dispose();
		if (file == null) {
			return null;
		}

		saveLastUsedFileFile(file);

		boolean hasExtension = false;
		String path = file.getAbsolutePath();
		for (String element : extensions) {
			if (path.toLowerCase().endsWith("." + element)) {
				hasExtension = true;
			}
		}

		if (!hasExtension) {
			file = new File(path + ".c");
		}
		return file;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getFunction() != null && context.getCCodeModel() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		File file = getFile(context.getDecompilerPanel());
		if (file == null) {
			return;
		}

		if (file.exists()) {
			if (OptionDialog.showYesNoDialog(context.getDecompilerPanel(),
				"Overwrite Existing File?",
				"Do you want to overwrite the existing file?") == OptionDialog.OPTION_TWO) {
				return;
			}
		}

		try {
			PrintWriter writer = new PrintWriter(new FileOutputStream(file));
			ClangTokenGroup grp = context.getCCodeModel();
			PrettyPrinter printer =
				new PrettyPrinter(context.getFunction(), grp, new IllegalCharCppTransformer());
			DecompiledFunction decompFunc = printer.print();
			writer.write(decompFunc.getC());
			writer.close();
			context.setStatusMessage(
				"Successfully exported function(s) to " + file.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(getClass(), context.getDecompilerPanel(), "Export to C Failed",
				"Error exporting to C: " + e);
		}
	}
}
