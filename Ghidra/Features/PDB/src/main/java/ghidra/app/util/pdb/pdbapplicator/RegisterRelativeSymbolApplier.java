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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractRegisterRelativeAddressMsSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;

/**
 * Applier for {@link AbstractRegisterRelativeAddressMsSymbol} symbols.
 */
public class RegisterRelativeSymbolApplier extends MsSymbolApplier
		implements NestableSymbolApplier {

	private AbstractRegisterRelativeAddressMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public RegisterRelativeSymbolApplier(DefaultPdbApplicator applicator,
			AbstractRegisterRelativeAddressMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	private boolean createFunctionVariable(FunctionSymbolApplier applier,
			AbstractRegisterRelativeAddressMsSymbol symbol)
			throws CancelledException, PdbException {
		Objects.requireNonNull(applier, "FunctionSymbolApplier cannot be null");
		Function function = applier.getFunction();

		if (function == null) {
			applicator.appendLogMsg("Could not create stack variable for non-existent function.");
			return false;
		}
		//Variable[] allVariables = function.getAllVariables();

		String registerName = symbol.getRegisterNameString();
		Register register = applicator.getRegister(registerName);
		Register sp = applicator.getProgram().getCompilerSpec().getStackPointer();
		if (register != sp) {
			// have seen fbp here.
			// TODO; can we do something more generic below that does not rely on stack frame?
			//  would like to do RSP + X, or RBP + X, or RDX + X.
			return false;
		}

		Integer registerChange = applier.getRegisterPrologChange(register);

		StackFrame stackFrame = function.getStackFrame();

		int baseParamOffset = applier.getBaseParamOffset();
		long frameSize = applier.getCurrentFrameSize();
//		long relativeOffset = symbol.getOffset() - applier.getCurrentFrameSize();
		if (registerChange == null) {
			registerChange = 0;
		}
		long relativeOffset = symbol.getOffset() + registerChange;
//		long relativeOffset = symbol.getOffset() + x;
//		if (relativeOffset > Integer.MAX_VALUE) {
//			applicator.appendLogMsg("Offset too large for our applier.");
//			//return false;
//		}
		int offset = (int) (relativeOffset & 0xffffffffL);

		RecordNumber typeRecord = symbol.getTypeRecordNumber();
		DataType dt = applicator.getCompletedDataType(typeRecord);
		if (dt != null) {
//			Variable m16 = stackFrame.getVariableContaining(-16);
//			Variable m8 = stackFrame.getVariableContaining(-8);
//			Variable x0 = stackFrame.getVariableContaining(0);
//			Variable x8 = stackFrame.getVariableContaining(8);
//			Variable x16 = stackFrame.getVariableContaining(16);
//			Variable x24 = stackFrame.getVariableContaining(24);
//			Variable x32 = stackFrame.getVariableContaining(32);
//			Variable x40 = stackFrame.getVariableContaining(40);
//			Variable x48 = stackFrame.getVariableContaining(48);
//			Variable x56 = stackFrame.getVariableContaining(56);
			Variable variable = stackFrame.getVariableContaining(offset);
			try {
				if (variable == null || variable.getStackOffset() != offset) {
					if (variable != null) {
						stackFrame.clearVariable(variable.getStackOffset());
					}
					try {
						variable = stackFrame.createVariable(symbol.getName(), offset, dt,
							SourceType.IMPORTED);
					}
					catch (DuplicateNameException e) {
						variable = stackFrame.createVariable(
							symbol.getName() + "@" + Integer.toHexString(offset), offset, dt,
							SourceType.IMPORTED);
					}
				}
				else {
					variable.setDataType(dt, false, true, SourceType.ANALYSIS);
					try {
						variable.setName(symbol.getName(), SourceType.IMPORTED);
					}
					catch (DuplicateNameException e) {
						variable.setName(symbol.getName() + "@" + Integer.toHexString(offset),
							SourceType.IMPORTED);
					}
				}
			}
			catch (InvalidInputException | DuplicateNameException e) {
				applicator.appendLogMsg("Unable to create stack variable " + symbol.getName() +
					" at offset " + offset + " in " + function.getName());
				return false;
			}
		}
		return true;
	}

	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		if (!applicator.getPdbApplicatorOptions().applyFunctionVariables()) {
			return;
		}
		if (applyToApplier instanceof FunctionSymbolApplier functionSymbolApplier) {
			createFunctionVariable(functionSymbolApplier, symbol);
		}
	}

	private AbstractRegisterRelativeAddressMsSymbol getValidatedSymbol(MsSymbolIterator iter,
			boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractRegisterRelativeAddressMsSymbol regRelSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return regRelSymbol;
	}

}
