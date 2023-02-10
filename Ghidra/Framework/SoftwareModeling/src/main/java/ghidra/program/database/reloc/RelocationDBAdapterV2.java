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
package ghidra.program.database.reloc;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressKeyRecordIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.VersionException;

class RelocationDBAdapterV2 extends RelocationDBAdapter {
	final static int VERSION = 2;
	
	private final static int V2_TYPE_COL = 0;
	private final static int V2_VALUE_COL = 1;

/* Do not remove the following commented out schema! It shows the version 2 relocation table schema. */
//	final static Schema SCHEMA = new Schema(
//		RelocationDBAdapterV2.VERSION, "Address", new Field[] { IntField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Type", "Values" });

	private Table relocTable;
	private AddressMap addrMap;

	/**
	 * Construct V2 read-only adapter
	 * @param handle database adapter
	 * @param addrMap address map for decode
	 * @throws IOException if database IO error occurs
	 * @throws VersionException throw if table schema is not V2
	 */
	RelocationDBAdapterV2(DBHandle handle, AddressMap addrMap)
			throws IOException, VersionException {
		this.addrMap = addrMap;
		relocTable = handle.getTable(TABLE_NAME);
		if (relocTable == null || relocTable.getSchema().getVersion() != VERSION) {
			throw new VersionException();
		}
	}

	@Override
	void add(Address addrKey, byte flags, int type, long[] values, byte[] bytes,
			String symbolName) {
		throw new UnsupportedOperationException();
	}

	@Override
	int getRecordCount() {
		return relocTable.getRecordCount();
	}

	@Override
	RecordIterator iterator() throws IOException {
		RecordIterator recIter = new AddressKeyRecordIterator(relocTable, addrMap);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	RecordIterator iterator(AddressSetView set) throws IOException {
		RecordIterator recIter =
			new AddressKeyRecordIterator(relocTable, addrMap, set, set.getMinAddress(), true);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	RecordIterator iterator(Address start) throws IOException {
		RecordIterator recIter = new AddressKeyRecordIterator(relocTable, addrMap, start, true);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	DBRecord adaptRecord(DBRecord rec) {
		if (rec == null) {
			return null;
		}
		DBRecord newRec = SCHEMA.createRecord(rec.getKey());
		newRec.setLongValue(ADDR_COL, rec.getKey()); // key was encoded address
		newRec.setByteValue(FLAGS_COL, getFlags(Status.UNKNOWN, 0));
		newRec.setIntValue(TYPE_COL, rec.getIntValue(V2_TYPE_COL));
		long[] values = new long[] { rec.getLongValue(V2_VALUE_COL) };
		newRec.setField(VALUE_COL, new BinaryCodedField(values));
		return newRec;
	}
}
