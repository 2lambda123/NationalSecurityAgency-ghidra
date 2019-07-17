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

import docking.ActionContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.UndefinedFunction;

public class DecompilerStructureVariableAction extends CreateStructureVariableAction {

	public DecompilerStructureVariableAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super(owner, tool, controller);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataType dt = null;
		boolean isThisParam = false;

		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
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

		// get the data type at the location and see if it is OK
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		HighVariable var = tokenAtCursor.getHighVariable();
		if (var != null && !(var instanceof HighConstant)) {
			dt = var.getDataType();
			isThisParam = testForAutoParameterThis(var, function);
		}

		if (dt == null) {
			return false;
		}

		adjustCreateStructureMenuText(dt, isThisParam);
		return true;
	}
}
