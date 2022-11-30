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
package ghidra.feature.vt.gui.actions;

import static ghidra.feature.vt.gui.actions.TableSelectionTrackingState.*;

import javax.swing.Icon;

import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import generic.theme.GIcon;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.util.HelpLocation;

public class MatchTableSelectionAction
		extends MultiStateDockingAction<TableSelectionTrackingState> {

	private static final String MENU_GROUP = VTPlugin.VT_SETTINGS_MENU_GROUP;

	public static final String NAME = "Table Selection Mode";

	private final VTMatchTableProvider matchTableProvider;

	public MatchTableSelectionAction(VTMatchTableProvider matchTableProvider) {
		super(NAME, VTPlugin.OWNER);
		this.matchTableProvider = matchTableProvider;

		setToolBarData(new ToolBarData(null, MENU_GROUP));
		setDescription("Adjust the Apply Mark-up Settings for Applying Matches");
		setEnabled(true);

		HelpLocation helpLocation =
			new HelpLocation("VersionTrackingPlugin", "Match_Table_Selection");
		setHelpLocation(helpLocation);

		Icon noSelectionTrackingIcon =
			new GIcon("icon.version.tracking.match.table.selection.track.none");
		Icon trackMatchSelectionIcon =
			new GIcon("icon.version.tracking.match.table.selection.track.match");
		Icon trackRowIndexSelectionIcon =
			new GIcon("icon.version.tracking.match.table.selection.track.row");

		ActionState<TableSelectionTrackingState> trackSelectedIndexActionState =
			new ActionState<>("Track Selected Index",
				trackRowIndexSelectionIcon, MAINTAIN_SELECTED_ROW_INDEX);
		trackSelectedIndexActionState.setHelpLocation(helpLocation);

		ActionState<TableSelectionTrackingState> trackMatchSelectionActionState =
			new ActionState<>("Track Selected Match",
				trackMatchSelectionIcon, MAINTAIN_SELECTED_ROW_VALUE);
		trackMatchSelectionActionState.setHelpLocation(helpLocation);

		ActionState<TableSelectionTrackingState> noSelectionTrackingActionState =
			new ActionState<>("No Selection Tracking",
				noSelectionTrackingIcon, NO_SELECTION_TRACKING);
		noSelectionTrackingActionState.setHelpLocation(helpLocation);

		addActionState(trackSelectedIndexActionState);
		addActionState(trackMatchSelectionActionState);
		addActionState(noSelectionTrackingActionState);

		setCurrentActionState(trackSelectedIndexActionState); // default
	}

	@Override
	public void actionStateChanged(ActionState<TableSelectionTrackingState> newActionState,
			EventTrigger trigger) {
		matchTableProvider.setTableSelectionMode(newActionState.getUserData());
	}
}
