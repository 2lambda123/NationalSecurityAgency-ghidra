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

import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;

public class EnumDataType extends GenericDataType implements Enum {

	private static final SettingsDefinition[] ENUM_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private Map<String, Long> nameMap; // name to value
	private TreeMap<Long, List<String>> valueMap; // value to names
	private Map<String, String> commentMap; // name to comment
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
		if (length < 1 || length > 8) {
			throw new IllegalArgumentException("unsupported enum length: " + length);
		}
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		this.length = length;
	}

	public EnumDataType(CategoryPath path, String name, int length, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		if (length < 1 || length > 8) {
			throw new IllegalArgumentException("unsupported enum length: " + length);
		}
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		this.length = length;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return ENUM_SETTINGS_DEFINITIONS;
	}

	@Override
	public long getValue(String valueName) throws NoSuchElementException {
		Long value = nameMap.get(valueName);
		if (value == null) {
			throw new NoSuchElementException("No value for " + valueName);
		}
		return value;
	}

	@Override
	public String getName(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return null;
		}
		return list.get(0);
	}

	@Override
	public String[] getNames(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return null;
		}
		return list.toArray(new String[0]);
	}

	@Override
	public String getComment(String valueName) {
		String comment = commentMap.get(valueName);
		if (comment == null) {
			comment = "";
		}
		return comment;
	}

	@Override
	public long[] getValues() {
		long[] values = valueMap.keySet().stream().mapToLong(Long::longValue).toArray();
		return values;
	}

	@Override
	public String[] getNames() {
		// names are first sorted by int value, then sub-sorted by name value
		List<String> names = new ArrayList<>();
		Collection<List<String>> values = valueMap.values();
		for (List<String> list : values) {
			Collections.sort(list);
			names.addAll(list);
		}
		return names.toArray(new String[0]);
	}

	@Override
	public int getCount() {
		return nameMap.size();
	}

	@Override
	public void add(String valueName, long value) {
		add(valueName, value, null);
	}

	@Override
	public void add(String valueName, long value, String comment) {
		bitGroups = null;
		checkValue(value);
		if (nameMap.containsKey(valueName)) {
			throw new IllegalArgumentException(valueName + " already exists in this enum");
		}

		nameMap.put(valueName, value);
		List<String> list = valueMap.computeIfAbsent(value, v -> new ArrayList<>());
		list.add(valueName);

		if (!StringUtils.isBlank(comment)) {
			commentMap.put(valueName, comment);
		}

	}

	@Override
	public void remove(String valueName) {
		bitGroups = null;
		Long value = nameMap.get(valueName);
		if (value == null) {
			return;
		}

		nameMap.remove(valueName);
		List<String> list = valueMap.get(value);
		Iterator<String> iter = list.iterator();
		while (iter.hasNext()) {
			if (valueName.equals(iter.next())) {
				iter.remove();
				break;
			}
		}
		if (list.isEmpty()) {
			valueMap.remove(value);
		}

		commentMap.remove(valueName);
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

	public void setLength(int newLength) {
		if (newLength == length) {
			return;
		}
		if (newLength < 1 || newLength > 8) {
			throw new IllegalArgumentException("Enum length must be between 1 and 8 inclusive");
		}

		checkValues(newLength);
		this.length = newLength;
	}

	private void checkValues(int newLength) {
		if (newLength == 8) {
			return; // all long values permitted
		}

		long newMaxValue = getMaxEnumValue(newLength);
		String[] names = getNames();
		for (String valueName : names) {
			long value = getValue(valueName);
			if (value > newMaxValue) {
				throw new IllegalArgumentException("Setting the length of this Enum to a size " +
					"that cannot contain the current value for \"" + valueName + "\" of 0x" +
					Long.toHexString(value) + "\nOld length: " + length + "; new length: " +
					newLength);
			}
		}
	}

	private void checkValue(long value) {
		if (length == 8) {
			return; // all long values permitted
		}

		long max = getMaxEnumValue(length);
		if (value > max) {
			throw new IllegalArgumentException(
				getName() + " enum value 0x" + Long.toHexString(value) +
					" is outside the range of 0x0 to 0x" + Long.toHexString(max));

		}
	}

	private long getMaxEnumValue(int bytes) {
		int bits = bytes * 8;     // number of bits used for the given size
		long power2 = 1L << bits; // 2^length is the number of values that 'bytes' can represent
		return power2 - 1;		  // max value is always 1 less than 2^length (0-based)
	}

	@Override
	public String getDescription() {
		return description == null ? "" : description;
	}

	@Override
	public void setDescription(String description) {
		this.description = description;
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
			return getRepresentation(value);
		}
		catch (MemoryAccessException e) {
			return "??";
		}
	}

	@Override
	public String getRepresentation(BigInteger bigInt, Settings settings, int bitLength) {
		return getRepresentation(bigInt.longValue());
	}

	private String getRepresentation(long value) {
		String valueName = getName(value);
		if (valueName == null) {
			valueName = getCompoundValue(value);
		}
		return valueName;
	}

	private String getCompoundValue(long value) {
		if (value == 0) {
			return "0";
		}
		List<BitGroup> list = getBitGroups();
		StringBuilder buf = new StringBuilder();
		for (BitGroup bitGroup : list) {
			long subValue = bitGroup.getMask() & value;
			if (subValue != 0) {
				String part = getName(subValue);
				if (part == null) {
					part = Long.toHexString(subValue).toUpperCase() + 'h';
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
			bitGroups = EnumValuePartitioner.partition(getValues(), getLength());
		}
		return bitGroups;
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

		if (!isEachValueEquivalent(enumm)) {
			return false;
		}
		return true;
	}

	private boolean isEachValueEquivalent(Enum enumm) {
		String[] names = getNames();
		String[] otherNames = enumm.getNames();
		try {
			for (int i = 0; i < names.length; i++) {
				if (!names[i].equals(otherNames[i])) {
					return false;
				}

				long value = getValue(names[i]);
				long otherValue = enumm.getValue(names[i]);
				if (value != otherValue) {
					return false;
				}

				String comment = getComment(names[i]);
				String otherComment = enumm.getComment(names[i]);
				if (!comment.equals(otherComment)) {
					return false;
				}
			}
			return true;
		}
		catch (NoSuchElementException e) {
			return false; // named element not found
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		bitGroups = null;
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}
		Enum enumm = (Enum) dataType;
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		setLength(enumm.getLength());
		String[] names = enumm.getNames();
		for (String valueName : names) {
			add(valueName, enumm.getValue(valueName), enumm.getComment(valueName));
		}
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name;
	}
}
