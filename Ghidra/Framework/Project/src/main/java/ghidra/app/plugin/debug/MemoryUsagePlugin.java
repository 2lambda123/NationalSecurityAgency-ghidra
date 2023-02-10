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
package ghidra.app.plugin.debug;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = UtilityPluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "VM Memory Display",
	description = "Plugin for displaying the VM memory information."
)
//@formatter:on
public class MemoryUsagePlugin extends Plugin implements ApplicationLevelOnlyPlugin {
	private DialogComponentProvider dialog;

	public MemoryUsagePlugin(PluginTool tool) {

		super(tool);

		setupActions();
	}

	@Override
	protected void dispose() {
		super.dispose();

		if (dialog != null) {
			dialog.dispose();
		}
	}

	private void setupActions() {
		DockingAction action;

		// add menu action for Hello->Program
		action = new DockingAction("Show VM memory", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showMemory();
			}
		};

		action.setEnabled(true);
		action.setHelpLocation(new HelpLocation("FrontEndPlugin", "ShowMemoryUsage"));
		String group = "YYY"; // trying to put this just above the last menu entry
		action.setMenuBarData(new MenuData(new String[] { "Help", "Show VM Memory" }, group));
		tool.addAction(action);

	}

	void clearDialog() {
		dialog = null;
	}

	public void showMemory() {
		if (dialog == null) {
			dialog = new ShowMemoryDialog(this);
		}
		else {
			dialog.toFront();
		}
	}
}
