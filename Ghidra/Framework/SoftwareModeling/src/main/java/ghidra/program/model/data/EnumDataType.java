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
package ghidra.program.model.data;

import java.util.*;

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongObjectHashtable;
import ghidra.util.datastruct.ObjectLongHashtable;
import ghidra.util.exception.NoValueException;

public class EnumDataType extends GenericDataType implements Enum {
	private ObjectLongHashtable<String> defs;
	private int length;
	private String description;
	private List<BitGroup> bitGroups;

	public EnumDataType(String name, int length) {
		this(CategoryPath.ROOT, name, length, null);
	}

	public EnumDataType(CategoryPath path, String name, int length) {
		this(path, name, length, null);
	}

	public EnumDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
		super(path, name, dtm);
		defs = new ObjectLongHashtable<>();
		this.length = length;
	}

	public EnumDataType(CategoryPath path, String name, int length, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		defs = new ObjectLongHashtable<>();
		this.length = length;
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDynamicallySized()
	 */
	@Override
	public boolean isDynamicallySized() {
		return false;
	}

	@Override
	public long getValue(String valueName) throws NoSuchElementException {
		try {
			return defs.get(valueName);
		}
		catch (NoValueException e) {
			throw new NoSuchElementException("No value for " + valueName);
		}
	}

	@Override
	public String getName(long value) {
		String[] names = defs.getKeys(new String[defs.size()]);
		for (String name1 : names) {
			try {
				long nameValue = defs.get(name1);
				if (nameValue == value) {
					return name1;
				}
			}
			catch (NoValueException e) {
				// can't happen
			}
		}
		return null;
	}

	@Override
	public long[] getValues() {
		String[] names = defs.getKeys(new String[defs.size()]);
		LongObjectHashtable<String> keyTable = new LongObjectHashtable<>();
		for (String name1 : names) {
			try {
				long value = defs.get(name1);
				keyTable.put(value, name1);
			}
			catch (NoValueException e) {
				// can't happen
			}
		}
		long[] values = keyTable.getKeys();
		Arrays.sort(values);
		return values;
	}

	@Override
	public String[] getNames() {
		String[] names = defs.getKeys(new String[defs.size()]);
		Arrays.sort(names);
		return names;
	}

	@Override
	public int getCount() {
		return defs.size();
	}

	@Override
	public void add(String valueName, long value) {
		bitGroups = null;
		checkValue(value);
		if (defs.contains(valueName)) {
			try {
				if (defs.get(valueName) == value) {
					return;
				}
			}
			catch (NoValueException e) {
			}
			throw new IllegalArgumentException(name + " enum value " + value + " already assigned");
		}
		defs.put(valueName, value);
	}

	private void checkValue(long value) {
		long max = (1L << (length * 8)) - 1;
		if (max > 0 && value > max) {
			throw new IllegalArgumentException(name + " enum value 0x" + Long.toHexString(value) +
				" is outside the range of 0x0 to 0x" + Long.toHexString(max));

		}
	}

	@Override
	public void remove(String valueName) {
		bitGroups = null;
		defs.remove(valueName);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		EnumDataType enumDataType =
			new EnumDataType(getCategoryPath(), getName(), getLength(), dtm);
		enumDataType.setDescription(getDescription());
		enumDataType.replaceWith(this);
		return enumDataType;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (getDataTypeManager() == dtm) {
			return this;
		}
		EnumDataType enumDataType =
			new EnumDataType(getCategoryPath(), getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		enumDataType.setDescription(description);
		enumDataType.replaceWith(this);
		return enumDataType;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public int getLength() {
		return length;
	}

	public void setLength(int length) {
		String[] names = getNames();
		for (String enumName : names) {
			long value = getValue(enumName);
			if (isTooBig(length, value)) {
				throw new IllegalArgumentException("Setting the length of this Enum to a size " +
					"that cannot contain the current value for \"" + enumName + "\" of " +
					Long.toHexString(value));
			}
		}
		this.length = length;
	}

	private boolean isTooBig(int testLength, long value) {
		long max = (1L << (testLength * 8)) - 1;
		if (max > 0 && value > max) {
			return true;
		}
		return false;
	}

	@Override
	public String getDescription() {
		return description == null ? "" : description;
	}

	@Override
	public void setDescription(String description) {
		this.description = description;
		stateChanged(null);
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int valueLength) {

		try {
			long value = 0;
			switch (valueLength) {
				case 1:
					value = buf.getByte(0);
					break;
				case 2:
					value = buf.getShort(0);
					break;
				case 4:
					value = buf.getInt(0);
					break;
				case 8:
					value = buf.getLong(0);
					break;
			}
			return new Scalar(valueLength * 8, value);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Scalar.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int valueLength) {
		try {
			long value = 0;
			switch (this.length) {
				case 1:
					value = buf.getByte(0) & 0xffL;
					break;
				case 2:
					value = buf.getShort(0) & 0xffffL;
					break;
				case 4:
					value = buf.getInt(0) & 0xffffffffL;
					break;
				case 8:
					value = buf.getLong(0);
					break;
			}
			String valueName = getName(value);
			if (valueName == null) {
				valueName = getCompoundValue(value);
			}
			return valueName;
		}
		catch (MemoryAccessException e) {
			return "??";
		}
	}

	private String getCompoundValue(long value) {
		if (value == 0) {
			return "0";
		}
		List<BitGroup> list = getBitGroups();
		StringBuffer buf = new StringBuffer();
		for (BitGroup bitGroup : list) {
			long subValue = bitGroup.getMask() & value;
			if (subValue != 0) {
				String part = getName(subValue);
				if (part == null) {
					part = getStringForNoMatchingValue(subValue);
				}
				if (buf.length() != 0) {
					buf.append(" | ");
				}
				buf.append(part);
			}
		}
		return buf.toString();
	}

	private List<BitGroup> getBitGroups() {
		if (bitGroups == null) {
			bitGroups = EnumValuePartitioner.partition(getValues());
		}
		return bitGroups;
	}

	private String getStringForNoMatchingValue(long value) {
		String valueName;
		String valueStr;
		if (value < 0 || value >= 32) {
			valueStr = "0x" + Long.toHexString(value);
		}
		else {
			valueStr = Long.toString(value);
		}
		valueName = "" + valueStr;
		return valueName;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null || !(dt instanceof Enum)) {
			return false;
		}
		Enum enumm = (Enum) dt;

		if (!DataTypeUtilities.equalsIgnoreConflict(name, enumm.getName()) ||
			length != enumm.getLength() || getCount() != enumm.getCount()) {
			return false;
		}
		String[] names = getNames();
		String[] otherNames = enumm.getNames();
		try {
			for (int i = 0; i < names.length; i++) {
				long value = getValue(names[i]);
				long otherValue = enumm.getValue(names[i]);
				if (!names[i].equals(otherNames[i]) || value != otherValue) {
					return false;
				}
			}
		}
		catch (NoSuchElementException e) {
			return false; // named element not found
		}
		return true;
	}

	@Override
	public void replaceWith(DataType dataType) {
		bitGroups = null;
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}
		Enum enumm = (Enum) dataType;
		defs.removeAll();
		setLength(enumm.getLength());
		String[] names = enumm.getNames();
		for (int i = 0; i < names.length; i++) {
			defs.put(names[i], enumm.getValue(names[i]));
		}
		stateChanged(null);
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeSizeChanged(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeSizeChanged(DataType dt) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dependsOn(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name == null ? null : name.toUpperCase();
	}
}
