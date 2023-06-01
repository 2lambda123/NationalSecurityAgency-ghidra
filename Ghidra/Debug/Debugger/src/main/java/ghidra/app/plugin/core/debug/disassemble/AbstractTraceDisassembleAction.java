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
package ghidra.app.plugin.core.debug.disassemble;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingActionContext;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.HelpLocation;

public abstract class AbstractTraceDisassembleAction extends DockingAction {
	protected final DebuggerDisassemblerPlugin plugin;

	public AbstractTraceDisassembleAction(DebuggerDisassemblerPlugin plugin, String name) {
		super(name, plugin.getName());
		this.plugin = plugin;
		setHelpLocation(new HelpLocation(plugin.getName(), "disassemble"));
	}

	protected abstract TracePlatform getPlatform(TraceProgramView view);

	protected abstract LanguageID getAlternativeLanguageID();

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof DebuggerListingActionContext lac)) {
			return;
		}
		TraceProgramView view = lac.getProgram();
		Address address = lac.getAddress();
		AddressSpace space = address.getAddressSpace();
		AddressSetView set;
		ProgramSelection selection = lac.getSelection();
		if (selection != null && !selection.isEmpty()) {
			set = selection;
		}
		else {
			set = view.getAddressFactory()
					.getAddressSet(space.getMinAddress(), space.getMaxAddress());
		}
		TracePlatform platform = getPlatform(view);
		LanguageID altLangID = getAlternativeLanguageID();
		TraceDisassembleCommand dis = new TraceDisassembleCommand(platform, address, set);
		dis.setInitialContext(DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
			platform.getLanguage(), altLangID, platform.mapHostToGuest(address)));
		dis.run(plugin.getTool(), view);
	}
}
