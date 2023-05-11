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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.address.Address;

@StructureMapping(structureName = "string")
public class GoString {

	@ContextField
	private StructureContext<GoString> context;

	@FieldMapping
	@MarkupReference("stringAddr")
	@EOLComment("stringValue")
	private long str;

	@FieldMapping
	private long len;

	public Address getStringAddr() {
		return context.getDataTypeMapper().getDataAddress(str);
	}

	public long getLength() {
		return len;
	}

	public String getStringValue() throws IOException {
		BinaryReader reader = context.getDataTypeMapper().getReader(str);
		return reader.readNextUtf8String((int) len);
	}
}
