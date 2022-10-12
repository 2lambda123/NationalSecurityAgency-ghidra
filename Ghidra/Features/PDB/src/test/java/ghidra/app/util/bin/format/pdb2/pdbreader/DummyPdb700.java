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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.StubMsf;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;

/**
 * This class is an extension of {@link Pdb700}, based on {@link AbstractPdb}, whose sole purpose
 *  is to allow for testing of internal components of {@link AbstractPdb} classes.  It is not
 *  part of the production PDB Reader.
 */
public class DummyPdb700 extends Pdb700 {

	private boolean debugInfoAvailable = true;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  Constructor for a dummy PDB used for testing
	 * @param tpiIndexMin int. The IndexMin to set/use for the {@link TypeProgramInterface}
	 * @param tpiIndexMaxExclusive int. MaxIndex+1 to set/use for the {@link TypeProgramInterface}
	 * @param ipiIndexMin int. The IndexMin to set/use for the {@link TypeProgramInterface}
	 * @param ipiIndexMaxExclusive int. MaxIndex+1 to set/use for the {@link TypeProgramInterface}
	 * @throws IOException upon file IO seek/read issues
	 * @throws PdbException upon unknown value for configuration or error in processing components
	 */
	public DummyPdb700(int tpiIndexMin, int tpiIndexMaxExclusive,
			int ipiIndexMin, int ipiIndexMaxExclusive) throws IOException, PdbException {
		super(new StubMsf(), new PdbReaderOptions());
		typeProgramInterface =
			new DummyTypeProgramInterface800(this, tpiIndexMin, tpiIndexMaxExclusive);
		debugInfo = new DummyDebugInfoNew(this);
		hasIdStream = true;
		itemProgramInterface =
			new DummyTypeProgramInterface800(this, ipiIndexMin, ipiIndexMaxExclusive);
		nameTable.forTestingOnlyAddOffsetNamePair(1, "NameTableTestString");
	}

	/**
	 * Set {@code true} to make existing debug information available; when set false,
	 * {@link #getDebugInfo()} returns null (as though it does not exist)
	 * @param setAvailable {@code true} to return actual value; @code false} to have it return null
	 */
	public void setDebugInfoAvailable(boolean setAvailable) {
		debugInfoAvailable = setAvailable;
	}

	@Override
	public PdbDebugInfo getDebugInfo() {
		return debugInfoAvailable ? debugInfo : null;
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a "type" record for a
	 *  particular record number
	 * @param recordNumber record number for the "type" AbstractMsType to be inserted
	 * @param type AbstractMsType to be inserted
	 * @return {@code true} if successful
	 */
	public boolean setTypeRecord(int recordNumber, AbstractMsType type) {
		return typeProgramInterface.setRecord(recordNumber, type);
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to add a "type" record that gets
	 *  its record number automatically assigned
	 * @param type "type" AbstractMsType to be inserted
	 * @return record number assigned
	 */
	public int addTypeRecord(AbstractMsType type) {
		return typeProgramInterface.addRecord(type);
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a "item" record for a
	 *  particular record number
	 * @param recordNumber record number for the "item" AbstractMsType to be inserted
	 * @param type AbstractMsType to be inserted
	 * @return {@code true} if successful
	 */
	public boolean setItemRecord(int recordNumber, AbstractMsType type) {
		return itemProgramInterface.setRecord(recordNumber, type);
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to add a "item" record that gets
	 *  its record number automatically assigned
	 * @param type "item" AbstractMsType to be inserted
	 * @return record number assigned
	 */
	public int addItemRecord(AbstractMsType type) {
		return itemProgramInterface.addRecord(type);
	}

}
