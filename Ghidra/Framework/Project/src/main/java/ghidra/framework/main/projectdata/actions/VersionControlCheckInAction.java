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

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.ChangedFilesDialog;
import ghidra.framework.main.datatree.CheckInTask;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;

/**
 * Action to check-in domain files to the repository.
 */
public class VersionControlCheckInAction extends VersionControlAction {

	private Component parent;

	/**
	 * Creates an action to check-in domain files to the repository.
	 * @param plugin the plug-in that owns this action.
	 * @param parent the component to be used as the parent of the check-in dialog.
	 */
	public VersionControlCheckInAction(Plugin plugin, Component parent) {
		super("CheckIn", plugin.getName(), plugin.getTool());
		this.parent = parent;
		Icon icon = new GIcon("icon.version.control.check.in");
		setPopupMenuData(new MenuData(new String[] { "Check In..." }, icon, GROUP));

		setToolBarData(new ToolBarData(icon, GROUP));

		setDescription("Check in file");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		doCheckIn(context.getSelectedFiles());
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

		List<DomainFile> domainFiles = context.getSelectedFiles();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.modifiedSinceCheckout()) {
				return true; // At least one checked out file selected.
			}
		}
		return false;
	}

	/**
	 * Determines the list of modified, checked out files and then checks them in.
	 */
	private void doCheckIn(List<DomainFile> domainFiles) {
		if (!checkRepositoryConnected()) {
			return;
		}
		List<DomainFile> checkedOut = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isCheckedOut() && domainFile.modifiedSinceCheckout()) {
				checkedOut.add(domainFile);
			}
		}

		if (checkedOut.isEmpty()) {
			Msg.showInfo(this, parent, "No Modified Files",
				"No checked-out and modified files in the given selection");
			return;
		}

		if (checkedOut.size() > 0) {
			checkIn(checkedOut);
		}
	}

	/**
	 * Check in the list of domain files. 
	 * Domain files that cannot be closed are skipped in the list.
	 * @param fileList list of DomainFile objects
	 */
	public void checkIn(List<DomainFile> fileList) {

		if (!checkRepositoryConnected()) {
			return;
		}

		ArrayList<DomainFile> changedList = new ArrayList<>();
		ArrayList<DomainFile> list = new ArrayList<>();
		for (DomainFile df : fileList) {
			if (df != null && df.canCheckin()) {
				if (!canCloseDomainFile(df)) {
					continue;
				}
				list.add(df);
				if (df.isChanged()) {
					changedList.add(df);
				}
			}
		}

		if (changedList.size() > 0) {
			ChangedFilesDialog dialog = new ChangedFilesDialog(tool, changedList);
			dialog.setCancelToolTipText("Cancel Check In");
			if (!dialog.showDialog()) { // blocks until the user hits Save or Cancel
				tool.setStatusInfo("Checkin canceled");
				return;
			}
			for (int i = 0; i < changedList.size(); i++) {
				DomainFile df = changedList.get(i);
				if (df.isChanged()) {
					list.remove(df);
				}
			}
		}
		if (list.size() > 0) {
			tool.execute(new CheckInTask(tool, list, parent));
		}
		else {
			Msg.showError(this, tool.getToolFrame(), "Checkin Failed", "Unable to checkin file(s)");
		}
	}

}
