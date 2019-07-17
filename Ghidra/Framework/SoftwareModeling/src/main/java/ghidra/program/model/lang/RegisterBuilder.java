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

public class RegisterBuilder {

	ArrayList<Register> registerList;
	HashMap<String, Register> registerMap;
	Address contextAddress;

	public RegisterBuilder() {
		registerList = new ArrayList<>();
		registerMap = new HashMap<>();
	}

	public void addRegister(String name, String description, Address address, int numBytes,
			boolean bigEndian, int typeFlags) {
		addRegister(name, description, address, numBytes, 0, numBytes * 8, bigEndian, typeFlags);
	}

	public void addRegister(String name, String description, Address address, int numBytes,
			int leastSignificantBit, int bitLength, boolean bigEndian, int typeFlags) {

		Register register = new Register(name, description, address, numBytes, leastSignificantBit,
			bitLength, bigEndian, typeFlags);
		addRegister(register);
	}

	public void addRegister(Register register) {
		Register aliasedReg = null;
		for (Register reg : registerList) {
			if (reg.getAddress().equals(register.getAddress()) &&
				reg.getLeastSignificantBit() == register.getLeastSignificantBit() &&
				reg.getBitLength() == register.getBitLength()) {
				// define as register alias
				reg.addAlias(register.getName());
				registerMap.put(register.getName(), reg);
				return;
			}
		}
		if (contextAddress == null && register.isProcessorContext()) {
			contextAddress = register.getAddress();
		}
		registerList.add(register);
		registerMap.put(register.getName(), register);
	}

	/**
	 * Returns the processor context address of the first
	 * context register added to this builder.
	 * @return context address
	 */
	public Address getProcessContextAddress() {
		return contextAddress;
	}

	public void removeRegister(String name) {
		Register register = registerMap.remove(name);
		if (register != null) {
			if (name.equals(register.getName())) {
				// name is primary - check for alias
				Iterator<String> iter = register.getAliases().iterator();
				if (!iter.hasNext()) {
					// no alias - remove register
					registerList.remove(register);
				}
				else {
					register.rename(iter.next());
				}
			}
			else {
				register.removeAlias(name);
			}
		}
	}

	public RegisterManager getRegisterManager() {
		return new RegisterManager(computeRegisters());
	}

	private Register[] computeRegisters() {
		List<Register> regList = new LinkedList<>();
		List<Register> unprocessed = new LinkedList<>(registerList);

		int bitSize = 1;
		while (unprocessed.size() > 0) {
			int nextLargerSize = Integer.MAX_VALUE;
			Iterator<Register> it = unprocessed.iterator();
			while (it.hasNext()) {
				Register register = it.next();
				if (register.getBitLength() == bitSize) {
					Register[] children = getChildren(register, regList);
					register.setChildRegisters(children);
					regList.add(register);
					it.remove();
				}
				else {
					nextLargerSize = Math.min(nextLargerSize, register.getBitLength());
				}
			}
			bitSize = nextLargerSize;
		}

		return registerList.toArray(new Register[registerList.size()]);
	}

	private Register[] getChildren(Register parent, List<Register> regList) {
		ArrayList<Register> children = new ArrayList<>();
		Iterator<Register> it = regList.iterator();
		while (it.hasNext()) {
			Register register = it.next();
			if (contains(parent, register)) {
				children.add(register);
				it.remove();
			}
		}
		return children.toArray(new Register[children.size()]);

	}

	private boolean contains(Register parent, Register child) {
		if (!parent.getAddressSpace().equals(child.getAddressSpace())) {
			return false;
		}

		long parentOffset = parent.getOffset();
		long childOffset = child.getOffset();
		if ((childOffset < parentOffset) || (childOffset +
			child.getMinimumByteSize() > parentOffset + parent.getMinimumByteSize())) {
			return false;
		}

		if (parent.getLeastSignificantBit() != 0) {
			return false;
		}
		if (parent.getBitLength() != parent.getMinimumByteSize() * 8) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the register with the given name;
	 * @param name the name of the register to retrieve
	 */
	public Register getRegister(String name) {
		return registerMap.get(name);
	}

	/**
	 * Rename a register.  This allows generic register names declared within the langauge 
	 * specification (*.slaspec) to be renamed for a processor variant specification (*.pspec).
	 * @param oldName original register name
	 * @param newName new register name
	 * @return true if rename was successful, else false
	 */
	public boolean renameRegister(String oldName, String newName) {
		if (registerMap.containsKey(newName)) {
			return false;
		}
		Register register = registerMap.get(oldName);
		if (register == null) {
			return false;
		}
		register.rename(newName);
		registerMap.remove(oldName);
		registerMap.put(newName, register);
		return true;
	}

	/**
	 * Set the group name for the specified register
	 * @param registerName register name
	 * @param groupName group name
	 * @return true if register was found, else false
	 */
	public boolean setGroup(String registerName, String groupName) {
		Register register = registerMap.get(registerName);
		if (register == null) {
			return false;
		}
		register.setGroup(groupName);
		return true;
	}

	/**
	 * Set a register flag for the specified register
	 * @param registerName register name
	 * @param registerFlag Register defined flag bit(s)
	 * @return true if register was found, else false
	 */
	public boolean setFlag(String registerName, int registerFlag) {
		Register register = registerMap.get(registerName);
		if (register == null) {
			return false;
		}
		register.setFlag(registerFlag);
		return true;
	}

	/**
	 * Add a vector lane size to the specified register.
	 * @param registerName register name
	 * @param registerFlag Register defined flag bit(s)
	 * @return true if register was found, else false
	 * @throws UnsupportedOperationException if register is unable to support the definition of 
	 * lanes.
	 * @throws IllegalArgumentException if {@code laneSizeInBytes} is invalid
	 */
	public boolean addLaneSize(String registerName, int laneSizeInBytes) {
		Register register = registerMap.get(registerName);
		if (register == null) {
			return false;
		}
		register.addLaneSize(laneSizeInBytes);
		return true;
	}
}
