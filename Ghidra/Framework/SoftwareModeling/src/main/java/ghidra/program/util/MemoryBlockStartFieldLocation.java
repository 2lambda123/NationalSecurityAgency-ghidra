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
/* Generated by Together */

package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/**
 * <CODE>BlockStartLocation</CODE> provides information about the location
 * (within a program) of an object that represents the start of a memory block.
 */
public class MemoryBlockStartFieldLocation extends CommentFieldLocation {

	/**
	  * Create a new BlockStartLocation.
	  *
	  * @param program the program of the location
	  * @param addr address of block
	  * @param componentPath the component path
	  * @param row component row
	  * @param charOffset character position of the location
	  * @param comment the location comment
	  * @param commentRow the comment row
	  */
	public MemoryBlockStartFieldLocation(Program program, Address addr, int[] componentPath, int row,
			int charOffset, String[] comment, int commentRow) {

		super(program, addr, componentPath, comment, CodeUnit.NO_COMMENT, row, charOffset);
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public MemoryBlockStartFieldLocation() {
	}

}
