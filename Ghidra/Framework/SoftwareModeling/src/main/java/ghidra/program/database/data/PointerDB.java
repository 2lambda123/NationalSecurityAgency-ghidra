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
package ghidra.program.database.data;

import java.io.IOException;

import db.Record;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation for a Pointer data type.
 */
class PointerDB extends DataTypeDB implements Pointer {

	private PointerDBAdapter adapter;
	private String displayName;
	private SettingsDefinition[] settingsDef;

	/**
	 * Constructor
	 * @param dataMgr
	 * @param cache
	 * @param adapter
	 * @param record
	 */
	public PointerDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			PointerDBAdapter adapter, Record record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(PointerDBAdapter.PTR_CATEGORY_COL);
	}

	@Override
	protected String doGetName() {
		String pointerName = PointerDataType.POINTER_NAME;
		DataType dt = getDataType();
		int storedLen = record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL); // -1 indicates default size
		if (dt == null) {
			if (storedLen > 0) {
				pointerName += Integer.toString(storedLen * 8);
			}
		}
		else {
			pointerName = dt.getName() + " *";
			if (storedLen > 0) {
				pointerName += Integer.toString(storedLen * 8);
			}
		}
		return pointerName;
	}

	/**
	 * @see ghidra.program.model.data.Pointer#getDataType()
	 */
	@Override
	public DataType getDataType() {
		lock.acquire();
		try {
			checkIsValid();
			return dataMgr.getDataType(record.getLongValue(PointerDBAdapter.PTR_DT_ID_COL));
		}
		finally {
			lock.release();
		}
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		lock.acquire();
		try {
			checkIsValid();
			if (settingsDef == null) {
				DataType dt = newPointer(getDataType());
				settingsDef = dt.getSettingsDefinitions();
			}
			return settingsDef;
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected void refreshName() {
		super.refreshName();
		displayName = null;
	}

	@Override
	protected boolean refresh() {
		try {
			Record rec = adapter.getRecord(key);
			if (rec != null) {
				record = rec;
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.data.DataType#clone(ghidra.program.model.data.DataTypeManager)
	 */
	@Override
	public final DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		// don't clone referenced data-type to avoid potential circular reference
		return new PointerDataType(getDataType(), isDynamicallySized() ? -1 : getLength(), dtm);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return clone(dtm);
	}

	/**
	 * @see ghidra.program.model.data.DataType#getName()
	 */
	@Override
	public String getDisplayName() {
		validate(lock);
		String localDisplayName = displayName;
		if (localDisplayName == null) {
			DataType dt = getDataType();
			if (dt == null) {
				localDisplayName = PointerDataType.POINTER_NAME;
				if (!isDynamicallySized()) {
					localDisplayName += Integer.toString(getLength() * 8);
				}
			}
			else {
				localDisplayName = dt.getDisplayName() + " *";
			}
			displayName = localDisplayName;
		}
		return localDisplayName;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.docking.settings.Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		lock.acquire();
		try {
			checkIsValid();
			DataType dataType = getDataType();
			if (dataType == null || dataType == DataType.DEFAULT) {
				return "addr";
			}
			return dataType.getMnemonic(settings) + " *";
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Pointer#isDynamicallySized()
	 */
	@Override
	public boolean isDynamicallySized() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL) <= 0;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		lock.acquire();
		try {
			checkIsValid();
			int len = record.getByteValue(PointerDBAdapter.PTR_LENGTH_COL);
			if (len <= 0) {
				len = dataMgr.getDataOrganization().getPointerSize();
			}
			return len;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		lock.acquire();
		try {
			checkIsValid();
			StringBuffer sbuf = new StringBuffer();
			if (!isDynamicallySized()) {
				sbuf.append(Integer.toString(getLength() * 8));
				sbuf.append("-bit ");
			}
			sbuf.append(PointerDataType.POINTER_NAME);
			DataType dt = getDataType();
			if (dt != null) {
				sbuf.append(" to ");
				if (dt instanceof Pointer) {
					sbuf.append(getDataType().getDescription());
				}
				else {
					sbuf.append(getDataType().getName());
				}
			}
			return sbuf.toString();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		lock.acquire();
		try {
			checkIsValid();

			// TODO: Which address space should pointer refer to ??

			return PointerDataType.getAddressValue(buf, getLength(),
				buf.getAddress().getAddressSpace());

		}
		catch (IllegalArgumentException exc) {
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		lock.acquire();
		try {
			checkIsValid();

			Address addr = (Address) getValue(buf, settings, length);
			if (addr == null) { // could not create address, so return "Not a pointer (NaP)"
				return "NaP";
			}
			return addr.toString();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == null) {
			return false;
		}
		if (this == dt) {
			return true;
		}
		if (!(dt instanceof Pointer)) {
			return false;
		}

		Pointer p = (Pointer) dt;
		DataType otherDataType = p.getDataType();
		if (isDynamicallySized() != p.isDynamicallySized()) {
			return false;
		}
		if (!isDynamicallySized() && (getLength() != p.getLength())) {
			return false;
		}

		DataType referencedDataType = getDataType();
		if (referencedDataType == null) {
			return otherDataType == null;
		}
		if (otherDataType == null) {
			return false;
		}

		// if they contain datatypes that have same ids, then we are essentially equivalent.
		if (DataTypeUtilities.isSameDataType(referencedDataType, otherDataType)) {
			return true;
		}

		return DataTypeUtilities.equalsIgnoreConflict(getDataType().getPathName(),
			otherDataType.getPathName());
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (newDt == this) {
			newDt = DataType.DEFAULT;
		}
		lock.acquire();
		try {
			String myOldName = getOldName();
			if (checkIsValid() && getDataType() == oldDt) {
				oldDt.removeParent(this);
				newDt.addParent(this);
				record.setLongValue(PointerDBAdapter.PTR_DT_ID_COL, dataMgr.getResolvedID(newDt));
				refreshName();
				if (!oldDt.getName().equals(newDt.getName())) {
					notifyNameChanged(myOldName);
				}
				try {
					adapter.updateRecord(record);
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
		if (getDataType() == dt) {
			dataMgr.addDataTypeToDelete(key);
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#setCategoryPath(ghidra.program.model.data.CategoryPath)
	 *
	 * Note: this does get called, but in a tricky way.  If externally, someone calls
	 * setCategoryPath, nothing happens because it is overridden in this class to do nothing.
	 * However, if updatePath is called, then this method calls super.setCategoryPath which
	 * bypasses the "overriddenness" of setCategoryPath, resulting in this method getting called.
	
	 */
	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(PointerDBAdapter.PTR_CATEGORY_COL, categoryID);
		adapter.updateRecord(record);
	}

	@Override
	protected void doSetNameRecord(String newName) throws InvalidNameException {
		throw new InvalidNameException("Can't set the name of an array!");
		// can't change the name of an pointer
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		lock.acquire();
		try {
			String myOldName = getOldName();
			if (checkIsValid() && dt == getDataType()) {
				refreshName();
				if (!getName().equals(myOldName)) {
					notifyNameChanged(myOldName);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setName(String name) throws InvalidNameException, DuplicateNameException {
		// do nothing - can't change the name of a pointer
	}

	@Override
	protected void updatePath(DataTypeDB dt) {
		if (dt == DataTypeUtilities.getBaseDataType(this)) {
			CategoryPath oldPath = getCategoryPath();
			CategoryPath currentPath = dt.getCategoryPath();
			if (!currentPath.equals(oldPath)) {
				try {
					super.setCategoryPath(currentPath);
				}
				catch (DuplicateNameException e) {
					// should not happen
				}
			}
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#setCategoryPath(ghidra.program.model.data.CategoryPath)
	 */
	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// not permitted to move - follows base type (see updatePath)
	}

	/**
	 * @see ghidra.program.model.data.DataType#dependsOn(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt != null && (myDt == dt || myDt.dependsOn(dt)));
	}

	/**
	 * @see ghidra.program.model.data.Pointer#newPointer(ghidra.program.model.data.DataType)
	 */
	@Override
	public Pointer newPointer(DataType dataType) {
		if (isDynamicallySized()) {
			return new PointerDataType(dataType, dataMgr);
		}
		return new PointerDataType(dataType, getLength(), dataMgr);
	}

	@Override
	public String getDefaultLabelPrefix() {
		return PointerDataType.POINTER_LABEL_PREFIX;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return PointerDataType.getLabelString(buf, settings, getLength(), options);
	}

	@Override
	public long getLastChangeTime() {
		return NO_LAST_CHANGE_TIME;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return DataType.NO_SOURCE_SYNC_TIME;
	}

	@Override
	public UniversalID getUniversalID() {
		// For now, arrays and pointers don't have UniversalIDs
		return null;
	}

	@Override
	protected void setUniversalID(UniversalID id) {
		// not applicable
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		// not applicable
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		// not applicable
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		// not applicable
	}

}
