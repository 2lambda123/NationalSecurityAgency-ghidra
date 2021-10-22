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

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.StringFormat;
import ghidra.util.classfinder.*;

/**
 * Provides an implementation of a 2 byte dataType that has not been defined yet as a
 * particular type of data in the program.
 */
public class Undefined2DataType extends Undefined {
	static {
		ClassTranslator.put("ghidra.program.model.data.Undefined2",
			Undefined2DataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public final static Undefined2DataType dataType = new Undefined2DataType();

	/**
	 * Constructs a new Undefined2 dataType
	 *
	 */
	public Undefined2DataType() {
		this(null);
	}

	public Undefined2DataType(DataTypeManager dtm) {
		super("undefined2", dtm);
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	public int getLength() {
		return 2;
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return "Undefined Word";
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

	private long getValue(MemBuffer buf) throws MemoryAccessException {
		long val = buf.getShort(0);
		return val & 0xffffl;
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		String val = "??";

		try {
			long b = getValue(buf);
			val = Long.toHexString(b).toUpperCase();
			val = StringFormat.padIt(val, 4, 'h', true);
		}
		catch (MemoryAccessException e) {
		}

		return val;
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return new Scalar(16, getValue(buf));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Undefined2DataType(dtm);
	}
}
