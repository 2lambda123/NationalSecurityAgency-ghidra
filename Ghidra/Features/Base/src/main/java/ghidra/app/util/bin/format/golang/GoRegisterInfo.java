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
package ghidra.app.util.bin.format.golang;

import java.util.List;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.Register;

/**
 * Immutable information about registers, alignment sizes, etc needed to allocate storage
 * for parameters during a function call.
 * <p>
 */
public class GoRegisterInfo {

	private final List<Register> intRegisters;
	private final List<Register> floatRegisters;
	private final int stackInitialOffset;
	private final int maxAlign;	// 4 or 8
	private final Register currentGoroutineRegister;	// always points to g
	private final Register zeroRegister;	// always contains a zero value
	private final boolean zeroRegisterIsBuiltin;	// zero register is provided by cpu, or is manually set

	GoRegisterInfo(List<Register> intRegisters, List<Register> floatRegisters,
			int stackInitialOffset, int maxAlign, Register currentGoroutineRegister,
			Register zeroRegister, boolean zeroRegisterIsBuiltin) {
		this.intRegisters = intRegisters;
		this.floatRegisters = floatRegisters;
		this.stackInitialOffset = stackInitialOffset;
		this.maxAlign = maxAlign;
		this.currentGoroutineRegister = currentGoroutineRegister;
		this.zeroRegister = zeroRegister;
		this.zeroRegisterIsBuiltin = zeroRegisterIsBuiltin;
	}

	public int getIntRegisterSize() {
		return maxAlign; // TODO: HACK: ?????
	}

	public int getMaxAlign() {
		return maxAlign;
	}

	public Register getCurrentGoroutineRegister() {
		return currentGoroutineRegister;
	}

	public Register getZeroRegister() {
		return zeroRegister;
	}

	public boolean isZeroRegisterIsBuiltin() {
		return zeroRegisterIsBuiltin;
	}

	public List<Register> getIntRegisters() {
		return intRegisters;
	}

	public List<Register> getFloatRegisters() {
		return floatRegisters;
	}

	public int getStackInitialOffset() {
		return stackInitialOffset;
	}

	public int getAlignmentForType(DataType dt) {
		while (dt instanceof TypeDef || dt instanceof Array) {
			if (dt instanceof TypeDef td) {
				dt = td.getBaseDataType();
			}
			if (dt instanceof Array a) {
				dt = a.getDataType();
			}
		}
		if (isIntType(dt) && isIntrinsicSize(dt.getLength())) {
			return Math.min(maxAlign, dt.getLength());
		}
		if (dt instanceof Complex8DataType /* golang complex64 */ ) {
			return 4;
		}
		if (dt instanceof AbstractFloatDataType) {
			return Math.min(maxAlign, dt.getLength());
		}
		return maxAlign;
	}

	static boolean isIntType(DataType dt) {
		return dt instanceof AbstractIntegerDataType || dt instanceof WideCharDataType ||
			dt instanceof WideChar16DataType || dt instanceof WideChar32DataType ||
			dt instanceof Enum || dt instanceof BooleanDataType;
	}

	static boolean isIntrinsicSize(int size) {
		return Integer.bitCount(size) == 1;
	}
}
