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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class OmfUnknownRecord extends OmfRecord {

	/**
	 * Create a new {@link OmfUnknownRecord}
	 *  
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException If an IO-related error occurred
	 */
	public OmfUnknownRecord(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		reader.setPointerIndex(reader.getPointerIndex() + getRecordLength());
	}
}
