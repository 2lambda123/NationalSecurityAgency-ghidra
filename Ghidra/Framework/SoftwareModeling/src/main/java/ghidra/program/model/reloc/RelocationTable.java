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
package ghidra.program.model.reloc;

import java.util.Iterator;
import java.util.List;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.reloc.Relocation.Status;

/**
 * An interface for storing the relocations defined in a program.
 * Table must preserve the order in which relocations are added such that
 * the iterators return them in the same order.
 */
public interface RelocationTable {
	/** Name of the relocatable property in the program information property list. */
	public static final String RELOCATABLE_PROP_NAME = "Relocatable";

	/**
	 * Adds a new relocation entry when the original bytes being replaced are to be specified.
	 * 
	 * @param addr the memory address where the relocation is required
	 * @param status relocation status (use {@link Status#UNKNOWN} if not known).
	 * @param type the type of relocation to perform
	 * @param values relocation-specific values which may be useful in diagnosing relocation; 
	 * may be null.
	 * @param bytes original memory bytes affected by relocation.  A null value may be
	 * passed but this case is deprecated (see {@link #add(Address, Status, int, long[], int, String)}.
	 * If null is specified and {@link Status#hasBytes()} is true a default number of original
	 * bytes will be assumed and obtained from the underlying memory {@link FileBytes} if possible.
	 * @param symbolName the name of the symbol being relocated; may be null 
	 * @return the newly added relocation object
	 */
	public Relocation add(Address addr, Status status, int type, long[] values, byte[] bytes,
			String symbolName);

	/**
	 * Adds a new relocation entry when the original bytes being replaced should be determined
	 * from the underlying {@link FileBytes}.
	 * 
	 * @param addr the memory address where the relocation is required
	 * @param status relocation status (use {@link Status#UNKNOWN} if not known).
	 * @param type the type of relocation to perform
	 * @param values relocation-specific values which may be useful in diagnosing relocation; 
	 * may be null.
	 * @param byteLength the number of bytes affected by this relocation.  This value is only
	 * used with a status of {@link Status#UNKNOWN}, {@link Status#APPLIED} or 
	 * {@link Status#APPLIED_OTHER}.  Valid range is 1..8 bytes.
	 * @param symbolName the name of the symbol being relocated; may be null 
	 * @return the newly added relocation object
	 */
	public Relocation add(Address addr, Status status, int type, long[] values, int byteLength,
			String symbolName);

	/**
	 * Returns the ordered list of relocations which have been defined for the specified address.
	 * In most cases there will be one or none, but in some cases multiple relocations may be
	 * applied to a single address. 
	 * @param addr the address where the relocation(s) are defined
	 * @return the ordered list of relocations which have been defined for the specified address.
	 */
	public List<Relocation> getRelocations(Address addr);

	/**
	 * Determine if the specified address has a relocation defined.
	 * @param addr memory address within program
	 * @return true if relocation defined, otherwise false
	 */
	public boolean hasRelocation(Address addr);

	/**
	 * Returns an iterator over all defined relocations (in ascending address order) located 
	 * within the program.
	 * @return ordered relocation iterator
	 */
	public Iterator<Relocation> getRelocations();

	/**
	 * Returns an iterator over all defined relocations (in ascending address order) located 
	 * within the program over the specified address set.
	 * @param set address set
	 * @return ordered relocation iterator
	 */
	public Iterator<Relocation> getRelocations(AddressSetView set);

	/**
	 * Returns the next relocation address which follows the specified address.
	 * @param addr starting point
	 * @return next relocation address after addr or null if none
	 */
	public Address getRelocationAddressAfter(Address addr);

	/**
	 * Returns the number of relocation in this table.
	 * @return the number of relocation in this table
	 */
	public int getSize();

	/**
	 * Returns true if this relocation table contains relocations for a relocatable binary.
	 * Some binaries may contain relocations, but not actually be relocatable. For example, ELF executables.
	 * @return true if this relocation table contains relocations for a relocatable binary
	 */
	public boolean isRelocatable();
}
