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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.ProgramContext;

import java.util.*;

abstract public class AbstractProgramContext implements ProgramContext, DefaultProgramContext {

	protected Map<String, Register> registerNameMap;
	protected Register[] registers;
	protected Register baseContextRegister;

	private boolean hasNonFlowingContext = false;
	private byte[] nonFlowingContextRegisterMask;
	private byte[] flowingContextRegisterMask;

	protected RegisterValue defaultDisassemblyContext;

	protected AbstractProgramContext(Register[] registers) {
		this.registers = registers;

		registerNameMap = new HashMap<String, Register>();
		initNameMap();

		if (baseContextRegister != null) {
			nonFlowingContextRegisterMask = baseContextRegister.getBaseMask().clone();
			Arrays.fill(nonFlowingContextRegisterMask, (byte) 0);
			flowingContextRegisterMask = nonFlowingContextRegisterMask.clone();
			initContextBitMasks(baseContextRegister);
		}
	}

	/**
	 * Set those bits in the nonFlowingContextRegisterMask which should not 
	 * flow with context.
	 * @param contextReg context register piece
	 */
	private void initContextBitMasks(Register contextReg) {
		byte[] subMask = contextReg.getBaseMask();
		if (!contextReg.followsFlow()) {
			hasNonFlowingContext = true;
			for (int i = 0; i < nonFlowingContextRegisterMask.length; i++) {
				nonFlowingContextRegisterMask[i] |= subMask[i];
				flowingContextRegisterMask[i] &= ~subMask[i];
			}
		}
		else {
			for (int i = 0; i < flowingContextRegisterMask.length; i++) {
				flowingContextRegisterMask[i] |= subMask[i];
			}
			if (contextReg.hasChildren()) {
				for (Register childReg : contextReg.getChildRegisters()) {
					initContextBitMasks(childReg);
				}
			}
		}
	}

	/**
	 * @return true if one or more non-flowing context registers fields
	 * have been defined within the base processor context register.
	 */
	@Override
	public final boolean hasNonFlowingContext() {
		return hasNonFlowingContext;
	}

	/**
	 * Modify register value to eliminate non-flowing bits
	 * @param value
	 * @return value suitable for flowing
	 */
	@Override
	public final RegisterValue getFlowValue(RegisterValue value) {
		if (value == null || !hasNonFlowingContext || !value.getRegister().isProcessorContext()) {
			return value;
		}
		return value.clearBitValues(nonFlowingContextRegisterMask);
	}

	/**
	 * Modify register value to only include non-flowing bits
	 * @param value
	 * @return new value or null
	 */
	@Override
	public final RegisterValue getNonFlowValue(RegisterValue value) {
		if (value == null || !hasNonFlowingContext || !value.getRegister().isProcessorContext()) {
			return null;
		}
		return value.clearBitValues(flowingContextRegisterMask);
	}

	protected void initNameMap() {
		baseContextRegister = null;
		for (Register register : registers) {
			registerNameMap.put(register.getName().toUpperCase(), register);
			if (register.isProcessorContext()) {
				baseContextRegister = register.getBaseRegister();
			}
			for (String alias : register.getAliases()) {
				registerNameMap.put(alias.toUpperCase(), register);
			}
		}
		if (baseContextRegister == null) {
			baseContextRegister =
				new Register("DEFAULT_CONTEXT", "DEFAULT_CONTEXT", Address.NO_ADDRESS, 4, true, 0);
		}
		defaultDisassemblyContext = new RegisterValue(baseContextRegister);

	}

	@Override
	public final Register[] getProcessorStateRegisters() {
		List<Register> list = new ArrayList<Register>();
		for (Register register : registers) {
			if (register.isProcessorContext()) {
				list.add(register);
			}
		}
		return list.toArray(new Register[list.size()]);
	}

	@Override
	public final Register getRegister(String name) {
		return registerNameMap.get(name.toUpperCase());
	}

	@Override
	public final String[] getRegisterNames() {
		List<String> list = new ArrayList<String>();
		for (Register register : registers) {
			list.add(register.getName());
		}
		return list.toArray(new String[list.size()]);
	}

	@Override
	public final Register[] getRegisters() {
		return registers;
	}

	@Override
	public final Register getBaseContextRegister() {
		return baseContextRegister;
	}

	@Override
	public final RegisterValue getDefaultDisassemblyContext() {
		return defaultDisassemblyContext;
	}

	@Override
	public final void setDefaultDisassemblyContext(RegisterValue value) {
		defaultDisassemblyContext = value;
	}

}
