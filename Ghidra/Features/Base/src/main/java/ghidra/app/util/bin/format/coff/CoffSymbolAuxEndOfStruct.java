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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class CoffSymbolAuxEndOfStruct implements CoffSymbolAux {

	private int     tagIndex;
	private byte [] unused1;
	private short   size; //of structure, union, or enumeration
	private byte [] unused2;

	CoffSymbolAuxEndOfStruct(BinaryReader reader, short magic) throws IOException {
		tagIndex = reader.readNextInt();
		unused1  = reader.readNextByteArray(2);
		size     = reader.readNextShort();
		if (magic == CoffMachineType.IMAGE_FILE_MACHINE_I960ROMAGIC ||
				magic == CoffMachineType.IMAGE_FILE_MACHINE_I960RWMAGIC) {
			unused2  = reader.readNextByteArray(16);
		} else {
			unused2  = reader.readNextByteArray(10);
		}
	}

	public int getTagIndex() {
		return tagIndex;
	}

	public byte [] getUnused1() {
		return unused1;
	}

	public short getSize() {
		return size;
	}

	public byte [] getUnused2() {
		return unused2;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
