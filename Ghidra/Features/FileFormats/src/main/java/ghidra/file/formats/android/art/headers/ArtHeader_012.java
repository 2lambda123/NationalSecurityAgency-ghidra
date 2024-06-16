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
package ghidra.file.formats.android.art.headers;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.art.ArtHeader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-wfc-release/runtime/image.cc#26">lollipop-mr1-wfc-release/runtime/image.c</a>
 */
public class ArtHeader_012 extends ArtHeader {

	protected int image_begin_;
	protected int image_size_;
	protected int image_bitmap_offset_;
	protected int image_bitmap_size_;
	protected int oat_checksum_;
	protected int oat_file_begin_;
	protected int oat_data_begin_;
	protected int oat_data_end_;
	protected int oat_file_end_;
	protected int patch_delta_;
	protected int image_roots_;
	protected int compile_pic_;

	public ArtHeader_012(BinaryReader reader) throws IOException {
		super(reader);
		parse(reader);
	}

	@Override
	protected void parse(BinaryReader reader) throws IOException {
		image_begin_ = reader.readNextInt();
		image_size_ = reader.readNextInt();
		image_bitmap_offset_ = reader.readNextInt();
		image_bitmap_size_ = reader.readNextInt();
		oat_checksum_ = reader.readNextInt();
		oat_file_begin_ = reader.readNextInt();
		oat_data_begin_ = reader.readNextInt();
		oat_data_end_ = reader.readNextInt();
		oat_file_end_ = reader.readNextInt();
		patch_delta_ = reader.readNextInt();
		image_roots_ = reader.readNextInt();
		compile_pic_ = reader.readNextInt();
	}

	@Override
	public int getImageBegin() {
		return image_begin_;
	}

	@Override
	public int getImageSize() {
		return image_size_;
	}

	/**
	 * Boolean (0 or 1) to denote if the image was compiled with --compile-pic option.
	 */
	public int getCompilePic() {
		return compile_pic_;
	}

	@Override
	public int getOatChecksum() {
		return oat_checksum_;
	}

	@Override
	public int getPointerSize() {
		return -1; //unsupported
	}

	@Override
	public int getOatFileBegin() {
		return oat_file_begin_;
	}

	@Override
	public int getOatFileEnd() {
		return oat_file_end_;
	}

	@Override
	public int getOatDataBegin() {
		return oat_data_begin_;
	}

	@Override
	public int getOatDataEnd() {
		return oat_data_end_;
	}

	@Override
	public void markup(Program program, TaskMonitor monitor) throws Exception {

	}

	@Override
	public int getArtMethodCountForVersion() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = (Structure) super.toDataType();

		structure.add(DWORD, "image_begin_", null);
		structure.add(DWORD, "image_size_", null);
		structure.add(DWORD, "image_bitmap_offset_", null);
		structure.add(DWORD, "image_bitmap_size_", null);
		structure.add(DWORD, "oat_checksum_", null);
		structure.add(DWORD, "oat_file_begin_", null);
		structure.add(DWORD, "oat_data_begin_", null);
		structure.add(DWORD, "oat_data_end_", null);
		structure.add(DWORD, "oat_file_end_", null);
		structure.add(DWORD, "patch_delta_", null);
		structure.add(DWORD, "image_roots_", null);
		structure.add(DWORD, "compile_pic_", null);

		return structure;
	}

}
