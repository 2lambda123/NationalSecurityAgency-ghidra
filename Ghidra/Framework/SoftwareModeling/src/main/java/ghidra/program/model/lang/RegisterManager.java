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
package ghidra.program.model.lang;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.OldGenericNamespaceAddress;

public class RegisterManager {

	Register[] registers;
	Register contextBaseRegister;
	Map<String, Register> registerNameMap = new HashMap<String, Register>();
	Map<RegisterSizeKey, Register> sizeMap = new HashMap<RegisterSizeKey, Register>();
	Map<Address, List<Register>> registerAddressMap = new HashMap<Address, List<Register>>();

	/**Collection of vector registers, sorted first by size and then by offset**/
	private TreeSet<Register> sortedVectorRegisters;

	class RegisterSizeKey {
		Address address;
		int size;

		public RegisterSizeKey(Address addr, int size) {
			address = getGlobalAddress(addr);
			this.size = size < 0 ? 0 : size;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (obj == this) {
				return true;
			}
			if (obj.getClass() != getClass()) {
				return false;
			}
			RegisterSizeKey other = (RegisterSizeKey) obj;
			return other.address.equals(address) && other.size == size;
		}

		@Override
		public int hashCode() {
			return address.hashCode() << 8 + size;
		}

		@Override
		public String toString() {
			return "{" + address.toString() + ", size = " + size + "}";
		}
	}

	private static Comparator<Register> registerSizeComparator = new Comparator<Register>() {
		@Override
		public int compare(Register r1, Register r2) {
			// Used for sorting largest to smallest
			return r2.getBitLength() - r1.getBitLength();
		}
	};

	RegisterManager(Register[] cookedRegisters) {
		registers = cookedRegisters;
		initialize();
	}

	private void initialize() {
		List<Register> registerList = new ArrayList<Register>(Arrays.asList(registers));
		Collections.sort(registerList, registerSizeComparator);
		for (Register reg : registerList) {
			registerNameMap.put(reg.getName(), reg);
			for (String alias : reg.getAliases()) {
				registerNameMap.put(alias, reg);
			}
			if (reg.isProcessorContext() && reg.isBaseRegister()) {
				contextBaseRegister = reg;
			}

			Address addr = reg.getAddress();
			List<Register> list = registerAddressMap.get(addr);
			if (list == null) {
				list = new ArrayList<Register>();
				registerAddressMap.put(addr, list);
			}
			list.add(reg);
			if (reg.isProcessorContext()) {
				continue;
			}

			if (reg.isBigEndian()) {
				populateSizeMapBigEndian(reg);
			}
			else {
				populateSizeMapLittleEndian(reg);
			}
		}
		// handle the register size 0 case;
		Collections.reverse(registerList);
		for (Register register : registerList) {
			sizeMap.put(new RegisterSizeKey(register.getAddress(), 0), register);
		}
	}

	private void populateSizeMapBigEndian(Register reg) {
		int regSize = reg.getMinimumByteSize();
		for (int i = 1; i <= regSize; i++) {
			Address address = reg.getAddress().add(regSize - i);
			sizeMap.put(new RegisterSizeKey(address, i), reg);
		}
	}

	private void populateSizeMapLittleEndian(Register reg) {
		int regSize = reg.getMinimumByteSize();
		for (int i = 1; i <= regSize; i++) {
			sizeMap.put(new RegisterSizeKey(reg.getAddress(), i), reg);
		}
	}

	/**
	 * Returns context base register or null if one has not been defined by the language.
	 */
	public Register getContextBaseRegister() {
		return contextBaseRegister;
	}

	/**
	 * Returns the largest register located at the specified address
	 * 
	 * @param addr
	 * @return largest register
	 */
	public Register getRegister(Address addr) {
		if (!addr.isRegisterAddress() && !addr.getAddressSpace().hasMappedRegisters()) {
			return null;
		}
		return sizeMap.get(new RegisterSizeKey(addr, 0));
	}

	/**
	 * Returns all registers located at the specified address
	 * 
	 * @param addr
	 * @return largest register
	 */
	public Register[] getRegisters(Address addr) {
		if (addr.isRegisterAddress() || addr.getAddressSpace().hasMappedRegisters()) {
			List<Register> list = registerAddressMap.get(getGlobalAddress(addr));
			if (list != null) {
				Register[] regs = new Register[list.size()];
				list.toArray(regs);
				return regs;
			}
		}
		return new Register[0];
	}

	private Address getGlobalAddress(Address addr) {
		if (addr instanceof OldGenericNamespaceAddress) {
			return ((OldGenericNamespaceAddress) addr).getGlobalAddress();
		}
		return addr;
	}

	/**
	 * Returns the smallest register at the specified address whose size is 
	 * greater than or equal the specified size.
	 * @param addr register address
	 * @param size the size of the register (in bytes).  A value of 0 will return the 
	 * largest register at the specified addr
	 * @return register
	 */
	public Register getRegister(Address addr, int size) {
		if (!addr.isRegisterAddress() && !addr.getAddressSpace().hasMappedRegisters()) {
			return null;
		}
		return sizeMap.get(new RegisterSizeKey(addr, size));
	}

	/**
	 * Returns the register with the given name;
	 * @param name the name of the register to retrieve
	 */
	public Register getRegister(String name) {
		return registerNameMap.get(name);
	}

	/**
	 * Return array of all registers.
	 * @return all registers
	 */
	public Register[] getRegisters() {
		return registers;
	}

	/**
	 * Returns the array of vector registers, sorted first by size and then by offset
	 * @return sorted vector registers
	 */
	public Register[] getSortedVectorRegisters() {
		if (sortedVectorRegisters == null) {
			sortedVectorRegisters = new TreeSet<Register>(RegisterManager::compareVectorRegisters);
			for (Register reg : getRegisters()) {
				if (reg.isVectorRegister()) {
					sortedVectorRegisters.add(reg);
				}
			}
		}
		return sortedVectorRegisters.toArray(new Register[0]);
	}

	/**
	 * Compares two vector registers, first by size (descending) and then by offset (ascending).
	 * @param reg1 vector register
	 * @param reg2 vector register
	 * @return result of comparison
	 */
	private static int compareVectorRegisters(Register reg1, Register reg2) {
		if (!(reg1.isVectorRegister() && reg2.isVectorRegister())) {
			throw new IllegalArgumentException("compareVectorRegisters can only be applied to vector registers!");
		}
		//want registers sorted in descending order of size
		int sizeComp = Integer.compare(reg2.getBitLength(), reg1.getBitLength());
		if (sizeComp != 0) {
			return sizeComp;
		}
		//want registers sorted in ascending order of offset
		return Integer.compare(reg1.getOffset(), reg2.getOffset());
	}

}
