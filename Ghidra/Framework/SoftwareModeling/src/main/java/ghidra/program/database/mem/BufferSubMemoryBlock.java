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
package ghidra.program.database.mem;

import java.io.IOException;

import db.DBBuffer;
import db.Record;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

/**
 * Implementation of SubMemoryBlock for blocks that store bytes in their own private database
 * buffers
 */
class BufferSubMemoryBlock extends SubMemoryBlock {
	final DBBuffer buf;

	BufferSubMemoryBlock(MemoryMapDBAdapter adapter, Record record) throws IOException {
		super(adapter, record);
		int bufferID = record.getIntValue(MemoryMapDBAdapter.SUB_SOURCE_ID_COL);
		buf = adapter.getBuffer(bufferID);
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

	@Override
	public byte getByte(long offset) throws IOException {
		return buf.getByte((int) (offset - startingOffset));
	}

	@Override
	public int getBytes(long offset, byte[] b, int off, int len) throws IOException {
		len = Math.min(len, (int) (length - (offset - startingOffset)));
		buf.get((int) (offset - startingOffset), b, off, len);
		return len;
	}

	@Override
	public void putByte(long offset, byte b) throws IOException {
		buf.putByte((int) (offset - startingOffset), b);
	}

	@Override
	public int putBytes(long offset, byte[] b, int off, int len) throws IOException {
		len = Math.min(len, (int) (length - offset - startingOffset));
		buf.put((int) (offset - startingOffset), b, off, len);
		return len;
	}

	@Override
	public void delete() throws IOException {
		buf.delete();
		super.delete();
	}

	@Override
	protected boolean join(SubMemoryBlock block) throws IOException {
		if (!(block instanceof BufferSubMemoryBlock)) {
			return false;
		}
		BufferSubMemoryBlock other = (BufferSubMemoryBlock) block;
		if (other.length + length > Memory.GBYTE) {
			return false;
		}
		buf.append(other.buf);
		setLength(length + other.length);
		adapter.deleteSubBlock(other.record.getKey());
		return true;
	}

	long getKey() {
		return record.getKey();
	}

	@Override
	protected MemoryBlockType getType() {
		return MemoryBlockType.DEFAULT;
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		int offset = (int) (memBlockOffset - startingOffset);
		long newLength = length - offset;
		length = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, length);
		adapter.updateSubBlockRecord(record);

		DBBuffer split = buf.split(offset);

		Record newSubRecord = adapter.createSubBlockRecord(0, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_BUFFER, split.getId(), 0);

		return new BufferSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "";
	}

	@Override
	protected ByteSourceRangeList getByteSourceRangeList(MemoryBlock block, Address start,
			long memBlockOffset,
			long size) {
		long sourceId = -buf.getId(); 	// buffers use negative id values; FileBytes use positive id values.
		ByteSourceRange bsRange =
			new ByteSourceRange(block, start, size, sourceId, memBlockOffset - startingOffset);
		return new ByteSourceRangeList(bsRange);
	}
}

