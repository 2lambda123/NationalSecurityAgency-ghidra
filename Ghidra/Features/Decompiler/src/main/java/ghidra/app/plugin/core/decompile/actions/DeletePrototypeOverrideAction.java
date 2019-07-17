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

import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class DeletePrototypeOverrideAction extends DockingAction {
	private final DecompilerController controller;

	public DeletePrototypeOverrideAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super("Remove Signature Override", owner);
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Remove Signature Override" }, "Decompile"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
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

		return getSymbol(controller) != null;
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

		CodeSymbol sym = getSymbol(controller);
		Function func = controller.getFunction();
		Program program = func.getProgram();
		SymbolTable symtab = program.getSymbolTable();
		int transaction = program.startTransaction("Remove Override Signature");
		boolean commit = true;
		if (!symtab.removeSymbolSpecial(sym)) {
			commit = false;
			Msg.showError(getClass(),
				controller.getDecompilerPanel(), "Removing Override Signature Failed", "Error removing override signature");
		}
		program.endTransaction(transaction, commit);
	}

	public static CodeSymbol getSymbol(DecompilerController controller) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return null;
		}
		Address addr = tokenAtCursor.getMinAddress();
		if (addr == null)
			return null;
		Function func = controller.getFunction();
		Namespace overspace = HighFunction.findOverrideSpace(func);
		if (overspace == null)
			return null;
		SymbolTable symtab = func.getProgram().getSymbolTable();
		SymbolIterator iter = symtab.getSymbols(overspace);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!sym.getName().startsWith("prt"))
				continue;
			if (!(sym instanceof CodeSymbol))
				continue;
			if (!sym.getAddress().equals(addr))
				continue;
			return (CodeSymbol) sym;
		}
		return null;

	}
}
