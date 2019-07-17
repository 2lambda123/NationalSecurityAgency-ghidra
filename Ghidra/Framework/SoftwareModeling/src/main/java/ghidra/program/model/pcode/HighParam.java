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
package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;

/**
 * 
 *
 * High-level function parameter
 */
public class HighParam extends HighLocal {
	private int slot;

	/**
	 * @param tp data type of variable
	 * @param store variable storage
	 * @param pc null or Address of PcodeOp which defines the representative
	 * @param slot parameter index starting at 0
	 * @param sym associated symbol
	 */
	public HighParam(DataType tp, Varnode rep, Address pc, int slot, HighSymbol sym) {
		super(tp, rep, null, pc, sym);
		this.slot = slot;
	}

	/**
	 * @return get the slot or parameter index
	 */
	public int getSlot() {
		return slot;
	}

	@Override
	protected int getFirstUseOffset() {
		return 0;
	}

}
