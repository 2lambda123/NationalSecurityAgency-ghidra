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
package ghidra.file.formats.android.oat.oatmethod;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-release/runtime/oat.h#163">lollipop-mr1-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat.h#165">ollipop-wear-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/oat.h#162">marshmallow-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/oat.h#172">nougat-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/nougat-mr1-release/runtime/oat.h#172">nougat-mr1-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat.h#172">oreo-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/oat.h#172">oreo-dr3-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/oat.h#176">oreo-m2-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/oat.h#177">pie-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/oat.h#150">android10-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/oat_file.h#75">android11-release/runtime/oat_file.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/oat_file.h#75">android12-release/runtime/oat_file.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/oat_file.h#75">android13-release/runtime/oat_file.h</a>
 * <br>
 */
public class OatMethodOffsets implements StructConverter {

	protected int code_offset_;

	public OatMethodOffsets(BinaryReader reader) throws IOException {
		code_offset_ = reader.readNextInt();
	}

	public int getCodeOffset() {
		return code_offset_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(OatMethodOffsets.class);
		dataType.setCategoryPath(new CategoryPath("/oat"));
		return dataType;
	}
}
