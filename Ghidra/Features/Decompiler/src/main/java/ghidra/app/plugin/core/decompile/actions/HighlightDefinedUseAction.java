/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

import java.util.HashSet;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class HighlightDefinedUseAction extends DockingAction {
	private final DecompilerController controller;

	public HighlightDefinedUseAction(String owner, DecompilerController controller) {
		super("Highlight Defined Use", owner);
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Highlight Def-use" }, "Decompile"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		return varnode != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(),
				context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked", "You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor);
		if (varnode != null) {
			HashSet<Varnode> varnodes = new HashSet<Varnode>();
			varnodes.add(varnode);
			decompilerPanel.clearHighlights();
			decompilerPanel.addVarnodeHighlights(varnodes, decompilerPanel.getDefaultHighlightColor(),varnode,varnode.getDef(),decompilerPanel.getDefaultSpecialColor());
			decompilerPanel.repaint();
		}
	}

}
