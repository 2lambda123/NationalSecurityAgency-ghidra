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
package ghidra.feature.vt.api.db;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import db.*;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class VTMatchTableDBAdapter {

	public enum ColumnDescription {
		TAG_KEY_COL(LongField.INSTANCE),
		MATCH_SET_COL(LongField.INSTANCE),
		SIMILARITY_SCORE_COL(StringField.INSTANCE),
		CONFIDENCE_SCORE_COL(StringField.INSTANCE),
		LENGTH_TYPE(StringField.INSTANCE),
		SOURCE_LENGTH_COL(IntField.INSTANCE),
		DESTINATION_LENGTH_COL(IntField.INSTANCE),
		ASSOCIATION_COL(LongField.INSTANCE);

		private final Field columnField;

		private ColumnDescription(Field columnField) {
			this.columnField = columnField;
		}

		public Field getColumnField() {
			return columnField;
		}

		public int column() {
			return ordinal();
		}

		private static String[] getColumnNames() {
			ColumnDescription[] columns = ColumnDescription.values();
			List<String> list = new LinkedList<String>();
			for (ColumnDescription column : columns) {
				list.add(column.name());
			}
			return list.toArray(new String[columns.length]);
		}

		private static Field[] getColumnFields() {
			ColumnDescription[] columns = ColumnDescription.values();
			Field[] fields = new Field[columns.length];
			for (int i = 0; i < fields.length; i++) {
				fields[i] = columns[i].getColumnField();
			}
			return fields;
		}
	}

	static String TABLE_NAME = "MatchTable";
	static Schema TABLE_SCHEMA = new Schema(0, "Key", ColumnDescription.getColumnFields(),
		ColumnDescription.getColumnNames());

	static VTMatchTableDBAdapter createAdapter(DBHandle dbHandle, long tableID) throws IOException {
		return new VTMatchTableDBAdapterV0(dbHandle, tableID);
	}

	static VTMatchTableDBAdapter getAdapter(DBHandle dbHandle, long tableID, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new VTMatchTableDBAdapterV0(dbHandle, tableID, openMode, monitor);
	}

	public abstract Record insertMatchRecord(VTMatchInfo info, VTMatchSetDB matchSet,
			VTAssociationDB associationDB, VTMatchTagDB tag) throws IOException;

	public abstract RecordIterator getRecords() throws IOException;

	abstract Record getMatchRecord(long matchRecordKey) throws IOException;

	abstract int getRecordCount();

	abstract void updateRecord(Record record) throws IOException;

	abstract boolean deleteRecord(long matchRecordKey) throws IOException;

	abstract RecordIterator getRecords(long associationID) throws IOException;
}
