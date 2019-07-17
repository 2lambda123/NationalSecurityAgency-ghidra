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

import db.Record;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

/**
 * Implementation of SubMemoryBlock for uninitialized blocks.
 */
class UninitializedSubMemoryBlock extends SubMemoryBlock {

	UninitializedSubMemoryBlock(MemoryMapDBAdapter adapter, Record record) {
		super(adapter, record);
		startingOffset = record.getLongValue(MemoryMapDBAdapter.SUB_START_OFFSET_COL);
	}

	@Override
	public boolean isInitialized() {
		return false;
	}

	@Override
	public byte getByte(long offset) throws MemoryAccessException {
		if (offset < startingOffset || offset >= startingOffset + length) {
			throw new IllegalArgumentException(
				"Offset " + offset + "is out of bounds. Should be in [" + startingOffset + "," +
					(startingOffset + length - 1));
		}
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	public int getBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	public void putByte(long offset, byte b) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	public int putBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		throw new MemoryAccessException("Attempted to read from uninitialized block");
	}

	@Override
	protected boolean join(SubMemoryBlock block) throws IOException {
		if (!(block instanceof UninitializedSubMemoryBlock)) {
			return false;
		}
		setLength(length + block.length);
		adapter.deleteSubBlock(block.record.getKey());
		return true;
	}

	@Override
	protected MemoryBlockType getType() {
		return MemoryBlockType.DEFAULT;
	}

	@Override
	protected SubMemoryBlock split(long memBlockOffset) throws IOException {
		// convert from offset in block to offset in this sub block
		long offset = memBlockOffset - startingOffset;
		long newLength = length - offset;
		length = offset;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, length);
		adapter.updateSubBlockRecord(record);

		Record newSubRecord = adapter.createSubBlockRecord(-1, 0, newLength,
			MemoryMapDBAdapter.SUB_TYPE_UNITIALIZED, 0, 0);

		return new UninitializedSubMemoryBlock(adapter, newSubRecord);
	}

	@Override
	protected String getDescription() {
		return "";
	}

	@Override
	protected ByteSourceRangeList getByteSourceRangeList(MemoryBlock block, Address start,
			long memBlockOffset,
			long size) {
		return new ByteSourceRangeList();
	}

}
