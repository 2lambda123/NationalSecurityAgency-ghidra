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

import java.util.*;

/**
 * This class represents Module Information component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class ModuleInformation {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected long modulePointer;
	protected SectionContribution sectionContribution;
	protected boolean writtenSinceOpen;
	// TODO: consider what to do (gets parsed for 600 between 500 items.  Want only in 600,
	//  but would have to break up the deserialize and dumpInternal methods.  Issue might be,
	//  however, that we want to see the default "false" value for 500 (see API).
	protected boolean ecSymbolicInformationEnabled;
	protected int bitfield;
	protected int spare;
	protected int indexToTSMList;
	protected int streamNumberDebugInformation; // unsigned 16-bit
	protected int sizeLocalSymbolsDebugInformation; //signed 32-bit
	protected int sizeLineNumberDebugInformation; //signed 32-bit
	protected int sizeC13StyleLineNumberInformation; //signed 32-bit
	protected int numFilesContributing; // unsigned 16-bit
	protected List<Integer> offsetsArray = new ArrayList<>(); // signed 32-bit
	protected List<String> filenamesArray = new ArrayList<>();

	protected String moduleName;
	protected String objectFileName;

	protected long nameIndexSourceFile; // unsigned 32-bit
	protected long nameIndexCompilerPdbPath; // unsigned 32-bit

	//==============================================================================================
	protected AbstractPdb pdb;

	private Map<Integer, String> filenameByOffset = new HashMap<>();

	//==============================================================================================
	// API
	//==============================================================================================
	public ModuleInformation(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Returns the number of files contributing to the module
	 * @return number of files
	 */
	public int getNumFilesContributing() {
		return numFilesContributing;
	}

	/**
	 * Returns list of offsets for the module
	 * @return offsets
	 */
	public List<Integer> getOffsetsArray() {
		return offsetsArray;
	}

	/**
	 * Returns list of file names for the module
	 * @return file names
	 */
	public List<String> getFilenamesArray() {
		return filenamesArray;
	}

	/**
	 * Returns the stream number containing debug information
	 * @return stream number
	 */
	public int getStreamNumberDebugInformation() {
		return streamNumberDebugInformation;
	}

	/**
	 * Returns the size of the local symbols debug information
	 * @return size of the local symbols debug information
	 */
	public int getSizeLocalSymbolsDebugInformation() {
		return sizeLocalSymbolsDebugInformation;
	}

	/**
	 * Returns the size of the older-style line number information
	 * @return size of the older-style line number information
	 */
	public int getSizeLineNumberDebugInformation() {
		return sizeLineNumberDebugInformation;
	}

	/**
	 * Returns the size of the C13-style line number information
	 * @return size of the C13-style line number information
	 */
	public int getSizeC13StyleLineNumberInformation() {
		return sizeC13StyleLineNumberInformation;
	}

	/**
	 * Returns the name of the module
	 * @return name of the module
	 */
	public String getModuleName() {
		return moduleName;
	}

	/**
	 * Returns {@link SectionContribution} of the module
	 * @return {@link SectionContribution} of the module
	 */
	public SectionContribution getSectionContribution() {
		return sectionContribution;
	}

	/**
	 * Returns the filename for the offset
	 * @param offset the offset for which the filename was stored
	 * @return the filename
	 */
	public String getFilenameByOffset(int offset) {
		return filenameByOffset.get(offset);
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Deserializes the module
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon error parsing a string name
	 */
	protected void deserialize(PdbByteReader reader) throws PdbException {
		modulePointer = reader.parseUnsignedIntVal();
		sectionContribution.deserialize(reader);
		bitfield = reader.parseUnsignedShortVal();
		writtenSinceOpen = ((bitfield & 0x01) == 0x01);
		bitfield >>= 1;
		spare = bitfield & 0x07f;
		bitfield >>= 1;
		indexToTSMList = bitfield & 0x0ff;
		ecSymbolicInformationEnabled = false;
		streamNumberDebugInformation = reader.parseUnsignedShortVal();
		sizeLocalSymbolsDebugInformation = reader.parseInt();
		sizeLineNumberDebugInformation = reader.parseInt();
		sizeC13StyleLineNumberInformation = reader.parseInt();
		numFilesContributing = reader.parseUnsignedShortVal(); //unsigned 16-bit
		reader.align4();
		reader.parseBytes(4); //placeholder for offsetsArray // unsigned 32-bit (unused?)
		parseAdditionals(reader);

//		for (int i = 0; i < numFilesContributing; i++) {
//			int offsetBufFilename = reader.parseInt();
//			offsetsArray.add(offsetBufFilename);
//		}
		reader.align4();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes the Additionals.  Abstract method filled in by instances to parse additional
	 *  data pertinent to themselves
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon error parsing a string name
	 */
	protected abstract void parseAdditionals(PdbByteReader reader) throws PdbException;

	/**
	 * Dumps the Additionals.  This method is for debugging only
	 * @return {@link String} of pretty output
	 */
	protected abstract String dumpAdditionals();

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Stores the filename for the offset given
	 * @param offset the offset for which to store the filename
	 * @param filename the filename to store
	 */
	protected void addFilenameByOffset(int offset, String filename) {
		filenameByOffset.put(offset, filename);
	}

	/**
	 * Dumps this module.  This method is for debugging only
	 * @return {@link String} of pretty output
	 */
	String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("ModuleInformation-------------------------------------------\n");
		builder.append("modulePointer: ");
		builder.append(modulePointer);
		builder.append("\n");
		builder.append(sectionContribution.dump());
		builder.append("\nwrittenSinceOpen: ");
		builder.append(writtenSinceOpen);

		builder.append("\necSymbolicInformationEnabled: ");
		builder.append(ecSymbolicInformationEnabled);

		builder.append("\nspare: ");
		builder.append(spare);
		builder.append("\nindexToTSMList: ");
		builder.append(indexToTSMList);
		builder.append("\nstreamNumberDebugInformation: ");
		builder.append(streamNumberDebugInformation);
		builder.append("\nsizeLocalSymbolsDebugInformation: ");
		builder.append(sizeLocalSymbolsDebugInformation);
		builder.append("\nsizeLineNumberDebugInformation: ");
		builder.append(sizeLineNumberDebugInformation);
		builder.append("\nsizeC13StyleLineNumberInformation: ");
		builder.append(sizeC13StyleLineNumberInformation);
		builder.append("\nnumFilesContributing: ");
		builder.append(numFilesContributing);

		builder.append(dumpAdditionals());

		builder.append("\nmoduleName: ");
		builder.append(moduleName);
		builder.append("\nobjectFileName: ");
		builder.append(objectFileName);

		builder.append("\nEnd ModuleInformation---------------------------------------\n");
		return builder.toString();
	}

}
