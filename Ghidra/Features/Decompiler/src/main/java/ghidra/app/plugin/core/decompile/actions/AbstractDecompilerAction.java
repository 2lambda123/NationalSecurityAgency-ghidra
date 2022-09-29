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
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.UndefinedFunction;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * A base class for {@link DecompilePlugin} actions that handles checking whether the
 * decompiler is busy.   Each action is responsible for deciding its enablement via
 * {@link #isEnabledForDecompilerContext(DecompilerActionContext)}.  Each action must implement
 * {@link #decompilerActionPerformed(DecompilerActionContext)} to complete its work.
 * 
 * <p>This parent class uses the {@link DecompilerActionContext} to check for the decompiler's
 * busy status.  If the decompiler is busy, then the action will report that it is enabled.  We
 * do this so that any keybindings registered for this action will get consumed and not passed up
 * to the global context.   Then, if the action is executed, this class does not call the child
 * class, but will instead show an information message indicating that the decompiler is busy.
 */
public abstract class AbstractDecompilerAction extends DockingAction {

	AbstractDecompilerAction(String name) {
		super(name, DecompilePlugin.class.getSimpleName());
	}

	AbstractDecompilerAction(String name, KeyBindingType kbType) {
		super(name, DecompilePlugin.class.getSimpleName(), kbType);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context instanceof DecompilerActionContext;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		return decompilerContext.checkActionEnablement(() -> {
			return isEnabledForDecompilerContext(decompilerContext);
		});
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		decompilerContext.performAction(() -> {
			decompilerActionPerformed(decompilerContext);
		});
	}

	/**
	 * Find the HighSymbol the decompiler associates with a specific address.
	 * @param addr is the specific address
	 * @param highFunction is the decompiler results in which to search for the symbol
	 * @return the matching symbol or null if no symbol exists
	 */
	private static HighSymbol findHighSymbol(Address addr, HighFunction highFunction) {
		HighSymbol highSymbol = null;
		if (addr.isStackAddress()) {
			LocalSymbolMap lsym = highFunction.getLocalSymbolMap();
			highSymbol = lsym.findLocal(addr, null);
		}
		else {
			GlobalSymbolMap gsym = highFunction.getGlobalSymbolMap();
			highSymbol = gsym.getSymbol(addr);
		}
		return highSymbol;
	}

	/**
	 * Track down the HighSymbol associated with a particular token.  The token may be directly attached to
	 * the symbol, or it may be a reference that needs to be looked up.
	 * @param token is the given token
	 * @param highFunction is the decompiler model of the function
	 * @return the associated HighSymbol or null if one can't be found
	 */
	public static HighSymbol findHighSymbolFromToken(ClangToken token, HighFunction highFunction) {
		if (highFunction == null) {
			return null;
		}
		HighVariable variable = token.getHighVariable();
		HighSymbol highSymbol = null;
		if (variable == null) {
			// Token may be from a variable reference, in which case we have to dig to find the actual symbol
			Function function = highFunction.getFunction();
			if (function == null) {
				return null;
			}
			Address storageAddress = getStorageAddress(token, function.getProgram());
			if (storageAddress == null) {
				return null;
			}
			highSymbol = findHighSymbol(storageAddress, highFunction);
		}
		else {
			highSymbol = variable.getSymbol();
		}
		return highSymbol;
	}

	/**
	 * Get the storage address of the variable attached to the given token, if any.
	 * The variable may be directly referenced by the token, or indirectly referenced as a point.
	 * @param tokenAtCursor is the given token
	 * @param program is the Program
	 * @return the storage Address or null if there is no variable attached
	 */
	private static Address getStorageAddress(ClangToken tokenAtCursor, Program program) {
		Varnode vnode = tokenAtCursor.getVarnode();
		Address storageAddress = null;
		if (vnode != null) {
			storageAddress = vnode.getAddress();
		}
		// op could be a PTRSUB, need to dig it out...
		else if (tokenAtCursor instanceof ClangVariableToken) {
			PcodeOp op = ((ClangVariableToken) tokenAtCursor).getPcodeOp();
			storageAddress = HighFunctionDBUtil.getSpacebaseReferenceAddress(program, op);
		}
		return storageAddress;
	}

	/**
	 * Get the structure/union associated with a field token
	 * @param tok is the token representing a field
	 * @return the structure/union which contains this field
	 */
	public static Composite getCompositeDataType(ClangToken tok) {
		// We already know tok is a ClangFieldToken
		ClangFieldToken fieldtok = (ClangFieldToken) tok;
		DataType dt = fieldtok.getDataType();
		if (dt == null) {
			return null;
		}
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof Composite) {
			return (Composite) dt;
		}
		return null;
	}

	/**
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

	protected static DataType chooseDataType(PluginTool tool, Program program,
			DataType currentDataType) {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataTypeSelectionDialog chooserDialog = new DataTypeSelectionDialog(tool, dataTypeManager,
			Integer.MAX_VALUE, AllowedDataTypes.FIXED_LENGTH);
		chooserDialog.setInitialDataType(currentDataType);
		tool.showDialog(chooserDialog);
		return chooserDialog.getUserChosenDataType();
	}

	protected Symbol getSymbol(DecompilerActionContext context) {

		// prefer the decompiler's function reference over the program location's address
		Function function = getFunction(context);
		if (function != null && !(function instanceof UndefinedFunction)) {
			return function.getSymbol();
		}

		Program program = context.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Address address = context.getAddress();
		if (address == null) {
			return null;
		}
		return symbolTable.getPrimarySymbol(address);
	}

	/**
	 * Get the function corresponding to the specified decompiler context.
	 * 
	 * @param context decompiler action context
	 * @return the function associated with the current context token or null if none identified.
	 */
	protected Function getFunction(DecompilerActionContext context) {
		ClangToken token = context.getTokenAtCursor();

		Function f = null;
		if (token instanceof ClangFuncNameToken) {
			f = DecompilerUtils.getFunction(context.getProgram(), (ClangFuncNameToken) token);
		}
		else {
			HighSymbol highSymbol = findHighSymbolFromToken(token, context.getHighFunction());
			if (highSymbol instanceof HighFunctionShellSymbol) {
				f = (Function) highSymbol.getSymbol().getObject();
			}
		}
		while (f != null && f.isThunk() && f.getSymbol().getSource() == SourceType.DEFAULT) {
			f = f.getThunkedFunction(false);
		}
		return f;
	}

	/**
	 * Subclasses return true if they are enabled for the given context
	 * 
	 * @param context the context
	 * @return true if enabled
	 */
	protected abstract boolean isEnabledForDecompilerContext(DecompilerActionContext context);

	/**
	 * Subclasses will perform their work in this method
	 * @param context the context
	 */
	protected abstract void decompilerActionPerformed(DecompilerActionContext context);
}
