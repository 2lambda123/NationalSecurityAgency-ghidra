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

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RenameVariableTask extends RenameTask {

	private HighVariable var;
	private Varnode exactSpot;
	private HighFunction hfunction;
	private Program program;
	private Function function;
	private boolean commitRequired; // Set to true if all parameters are committed before renaming
	private SourceType srctype;		// Desired source type for the variable being renamed
	private SourceType signatureSrcType;	// Signature source type of the function (which will be preserved)

	public RenameVariableTask(PluginTool tool, String old, HighFunction hfunc, HighVariable v,
			Varnode ex, SourceType st) {
		super(tool, old);
		var = v;
		exactSpot = ex;
		hfunction = hfunc;
		function = hfunc.getFunction();
		program = function.getProgram();
		srctype = st;
		signatureSrcType = function.getSignatureSource();
	}

	@Override
	public void commit() throws DuplicateNameException, InvalidInputException {
		if (commitRequired) {
			HighFunctionDBUtil.commitParamsToDatabase(hfunction, false, signatureSrcType);
			if (signatureSrcType != SourceType.DEFAULT) {
				HighFunctionDBUtil.commitReturnToDatabase(hfunction, signatureSrcType);
			}
		}
		HighFunctionDBUtil.updateDBVariable(var, newName, null, srctype);
	}

	@Override
	public boolean isValid(String newNm) {
		newName = newNm;
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		if (localSymbolMap.containsVariableWithName(newName) || isSymbolInFunction(newName)) {
			errorMsg = "Duplicate name";
			return false;
		}
		commitRequired = RetypeVariableAction.checkFullCommit(var, hfunction);
		if (commitRequired) {
			exactSpot = null; // Don't try to split out if we need to commit
		}

		if (exactSpot != null) { // The user pointed at a particular usage, not just the vardecl
			try {
				var = hfunction.splitOutMergeGroup(var, exactSpot);
			}
			catch (PcodeException e) {
				errorMsg = "Rename Failed: " + e.getMessage();
				return false;
			}
		}
		return true;
	}

	private boolean isSymbolInFunction(String name) {
		SymbolTable symbolTable = program.getSymbolTable();
		return !symbolTable.getSymbols(name, function).isEmpty();
	}

	@Override
	public String getTransactionName() {
		return "Rename Local Variable";
	}
}
