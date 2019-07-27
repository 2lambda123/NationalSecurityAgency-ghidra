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
package ghidra.app.util.bin.format.pdb;

import java.util.*;

import ghidra.app.util.bin.format.pdb.PdbParser.PdbFileType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Storage of PDB-related attributes
 */
public class PdbProgramAttributes {

	private String pdbAge;
	private String pdbGuid;
	private String pdbSignature;

	// A formatted string that combines 'pdbAge' and one of ['pdbGuid' or 'pdbSignature'].
	// This string is used to uniquely identify the PDB version and is used here:
	//   - as part of the URL when retrieving a PDB from the Symbol Server
	//   - as a directory name when the PDB is stored locally
	private String guidAgeCombo;

	private String pdbFile;
	private boolean pdbLoaded;
	private boolean programAnalyzed;
	private String executablePath;

	private List<String> potentialPdbFilenames = null;

	public PdbProgramAttributes(Program program) {

		Options propList = program.getOptions(Program.PROGRAM_INFO);

		pdbGuid = propList.getString(PdbParserConstants.PDB_GUID, (String) null);
		pdbAge = propList.getString(PdbParserConstants.PDB_AGE, (String) null);
		pdbLoaded = propList.getBoolean(PdbParserConstants.PDB_LOADED, false);
		programAnalyzed = propList.getBoolean(Program.ANALYZED, false);
		pdbSignature = propList.getString(PdbParserConstants.PDB_SIGNATURE, (String) null);
		pdbFile = propList.getString(PdbParserConstants.PDB_FILE, (String) null);

		executablePath = program.getExecutablePath();

		createGuidAgeString();
	}

	// Used for testing purposes to make a "dummy" object 
	public PdbProgramAttributes(String guid, String age, boolean loaded, boolean analyzed,
			String signature, String file, String execPath) {
		pdbGuid = guid;
		pdbAge = age;
		pdbLoaded = loaded;
		programAnalyzed = analyzed;
		pdbSignature = signature;
		pdbFile = file;

		executablePath = execPath;
		createGuidAgeString();
	}

	public String getPdbAge() {
		return pdbAge;
	}

	public String getPdbGuid() {
		return pdbGuid;
	}

	public String getPdbSignature() {
		return pdbSignature;
	}

	public String getPdbFile() {
		return pdbFile;
	}

	public boolean isPdbLoaded() {
		return pdbLoaded;
	}

	public String getExecutablePath() {
		return executablePath;
	}

	public boolean isProgramAnalyzed() {
		return programAnalyzed;
	}

	/**
	 * Get a potential list of PDB filenames using the 'pdbFile' and 'executablePath' attributes.
	 * 
	 * @return  list of unique, potential PDB filenames
	 */
	public List<String> getPotentialPdbFilenames() {
		if (potentialPdbFilenames == null) {

			// Want to preserve add order while only keeping unique entries
			Set<String> setOfPotentialFilenames = new LinkedHashSet<String>();

			if (pdbFile != null) {
				setOfPotentialFilenames.add(getFilename(pdbFile).toLowerCase());
				setOfPotentialFilenames.add(pdbFile);
			}

			// getExecutablePath can return "unknown"
			if (!executablePath.equals("unknown")) {
				String executableFilename = getFilename(executablePath);
				setOfPotentialFilenames.add(getBinaryBasename(executableFilename).toLowerCase() +
					PdbFileType.PDB.toString());
			}

			potentialPdbFilenames = new ArrayList<String>(setOfPotentialFilenames);
		}

		return potentialPdbFilenames;
	}

	public String getGuidAgeCombo() {
		return guidAgeCombo;
	}

	private String getBinaryBasename(String filename) {
		String binaryName = filename;
		int dotpos = binaryName.lastIndexOf('.');

		// Checking for > 0 because it's not useful if the last '.' is at index 0
		if (dotpos > 0) {
			binaryName = binaryName.substring(0, dotpos);
		}

		return binaryName;
	}

	/**
	 *  Reformat GUID or signature and add age to create the guidAgeString. This 
	 *  string is used as part of the path that stores the PDB file.
	 * 
	 *  When GUID (preferred) is not available, signature is used in its place.
	 */
	private void createGuidAgeString() {

		if ((pdbGuid == null && pdbSignature == null) || pdbAge == null) {
			guidAgeCombo = null;
			return;
		}

		guidAgeCombo = (pdbGuid == null) ? pdbSignature : pdbGuid;
		guidAgeCombo = guidAgeCombo.replaceAll("-", "");
		guidAgeCombo = guidAgeCombo.toUpperCase();

		int pdbAgeDecimal = Integer.parseInt(pdbAge, 16);
		guidAgeCombo += pdbAgeDecimal;
	}

	/**
	 * Extracts the actual file name from a full path.
	 * 
	 * Note that Java methods such as File.getName() and Path.getFileName() won't work here, because
	 * they are OS-specific. If we are on a Linux machine and calling getName("C:\\Windows\\temp.exe"),
	 * the Java method will return "C:\\Windows\\temp.exe" and not the expected "temp.exe".
	 * 
	 * This method also accounts for non-standard paths where both types of slashes are used.
	 * 
	 * @param fullPath from which to extract the filename
	 * @return the name of the file specified by the fullPath
	 */
	private static String getFilename(String fullPath) {
		// Remove any trailing slashes
		String editedPath = fullPath;
		editedPath = editedPath.replaceAll("[\\/]$", "");

		int lastIndexForwardSlash = editedPath.lastIndexOf('/');
		int lastIndexBackSlash = editedPath.lastIndexOf('\\');

		if (lastIndexForwardSlash == -1 && lastIndexBackSlash == -1) {
			return editedPath;
		}

		int indexToUse =
			(lastIndexForwardSlash > lastIndexBackSlash) ? lastIndexForwardSlash
					: lastIndexBackSlash;

		return editedPath.substring(indexToUse + 1);
	}
}
