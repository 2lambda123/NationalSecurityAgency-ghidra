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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

public abstract class CreateStructureVariableAction extends DockingAction {
	protected final DecompilerController controller;
	private final PluginTool tool;

	public CreateStructureVariableAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super("Recover Structure Variable", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Auto Create Structure" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_OPEN_BRACKET, InputEvent.SHIFT_DOWN_MASK));
	}

	static boolean testForAutoParameterThis(HighVariable var, Function f) {
		if (var instanceof HighParam) {
			int slot = ((HighParam) var).getSlot();
			Parameter parameter = f.getParameter(slot);
			if ((parameter != null) &&
				(parameter.getAutoParameterType() == AutoParameterType.THIS)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public abstract boolean isEnabledForContext(ActionContext context);

	/**
	 * Change the menu text for the create/fill structure action based on the current
	 * data type at the location and whether the location is for a "this" parameter.
	 * @param dt the current data type.
	 * @param isThisParam true indicates the data type is for a "this" parameter.
	 */
	protected void adjustCreateStructureMenuText(DataType dt, boolean isThisParam) {

		// rip off any multi-level pointers
		while (dt instanceof Pointer) {
			dt = ((Pointer) dt).getDataType();
		}

		String menuString = "Auto Create Structure";
		if (dt instanceof Structure) {
			if (isThisParam) {
				menuString = "Auto Fill in Class Structure";
			}
			else {
				menuString = "Auto Fill in Structure";
			}
		}
		else {
			if (isThisParam) {
				menuString = "Auto Create Class Structure";
			}
		}
		getPopupMenuData().setMenuItemName(menuString);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ProgramLocation location = null;
		Program program = null;
		if (context instanceof DecompilerActionContext) {
			DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
			if (decompilerActionContext.isDecompiling()) {
				Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
					"Decompiler Action Blocked",
					"You cannot perform Decompiler actions while the Decompiler is busy");
				return;
			}

			location = decompilerActionContext.getLocation();
			program = decompilerActionContext.getProgram();
		}
		else if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			// get the data type at the location and see if it is OK
			// make sure what we are over can be mapped to decompiler
			// param, local, etc...

			location = listingContext.getLocation();
			program = listingContext.getProgram();
		}
		else {
			return;
		}

		FillOutStructureCmd task = new FillOutStructureCmd(program, location, tool);
		task.applyTo(program);

//    	if (commitRequired) {
//    		int resp = OptionDialog.showOptionDialog(tool.getToolFrame(), "Parameter Commit Required",
//    				"Retyping a parameter requires all other parameters to be committed!\nContinue with retype?", "Continue");
//    		if (resp != OptionDialog.OPTION_ONE) {
//    			return;
//    		}
//    	}
	}
}
