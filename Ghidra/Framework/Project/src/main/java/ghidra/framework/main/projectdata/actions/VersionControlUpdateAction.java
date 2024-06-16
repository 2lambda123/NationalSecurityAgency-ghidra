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
package ghidra.framework.main.projectdata.actions;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

/**
 * Action to update the current checked out domain file to contain the changes 
 * which have been checked in to the repository since our file's version was checked out.
 * The update occurs by merging the changes from the repository's latest version into 
 * the current copy of the checked out file.
 */
public class VersionControlUpdateAction extends VersionControlAction {

	/**
	 * Creates an action for updating domain files that are checked out.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlUpdateAction(Plugin plugin) {
		super("Update", plugin.getName(), plugin.getTool());
		Icon icon = new GIcon("icon.projectdata.version.control.update");
		setPopupMenuData(new MenuData(new String[] { "Update..." }, icon, GROUP));
		setToolBarData(new ToolBarData(icon, GROUP));
		setDescription("Update checked out file with latest version");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		update(context.getSelectedFiles());
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

		List<DomainFile> providedList = context.getSelectedFiles();
		for (DomainFile domainFile : providedList) {
			if (domainFile.isVersioned() &&
				(domainFile.getLatestVersion() != domainFile.getVersion())) {
				return true; // At least one checked out file that has a newer version in the repository.
			}
		}
		return false;
	}

	/**
	 * Gets the list of domain files from the provider and updates each file 
	 * by merging the changes from the repository into the current copy.
	 */
	private void update(List<DomainFile> domainFiles) {
		if (!checkRepositoryConnected()) {
			return;
		}

		List<DomainFile> updateList = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile != null && domainFile.canMerge()) {
				if (!canCloseDomainFile(domainFile)) {
					continue;
				}
				updateList.add(domainFile);
			}
		}
		AppInfo.getFrontEndTool().merge(tool, updateList, new TaskListener() {

			@Override
			public void taskCompleted(Task task) {
				// don't care
			}

			@Override
			public void taskCancelled(Task task) {
				// don't care
			}
		});
	}

}
