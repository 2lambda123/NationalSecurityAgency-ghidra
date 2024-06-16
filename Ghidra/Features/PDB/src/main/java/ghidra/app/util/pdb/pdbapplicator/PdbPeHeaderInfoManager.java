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
package ghidra.app.util.pdb.pdbapplicator;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;

/**
 * Manages PE Header information that we need that is not retained in the Program.
 *  Current data includes CLI-Managed information and original image base.
 */
public class PdbPeHeaderInfoManager {

	private DefaultPdbApplicator applicator;
	private boolean initComplete = false;

	private CliStreamMetadata metadataStream;
	private boolean isDll = false;
	private boolean isAslr = false;
	private long originalImageBase = 0;

	/**
	 * Manager of CLI-related tables that we might need access to for PDB processing.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working (used for
	 *  logging purposes only).
	 */
	PdbPeHeaderInfoManager(DefaultPdbApplicator applicator) {
		Objects.requireNonNull(applicator, "applicator may not be null");
		this.applicator = applicator;
	}

	private synchronized void initialize() {
		if (initComplete) {
			return;
		}
		retrievePEHeaderInformation();
		initComplete = true;
	}

	boolean isDll() {
		initialize();
		return isDll;
	}

	boolean isAslr() {
		initialize();
		return isAslr;
	}

	long getOriginalImageBase() {
		initialize();
		return originalImageBase;
	}

	/**
	 * Get CLI metadata for specified tableNum and rowNum within the CLI
	 * metadata stream.
	 * @param tableNum CLI metadata stream table index
	 * @param rowNum table row number
	 * @return CLI metadata or null if specified tableNum not found
	 * @throws PdbException if CLI metadata stream is not found in program file bytes
	 * @throws IndexOutOfBoundsException if specified rowNum is invalid
	 */
	CliAbstractTableRow getCliTableRow(int tableNum, int rowNum)
			throws PdbException, IndexOutOfBoundsException {
		initialize();
		if (metadataStream == null) {
			throw new PdbException("CliStreamMetadata is null");
		}
		CliAbstractTable table = metadataStream.getTable(tableNum);
		if (table == null) {
			return null;
		}
		return table.getRow(rowNum);
	}

	/**
	 * Get CLI stream metadata.  Results directly filled into data members
	 */
	private void retrievePEHeaderInformation() {
		Program program = applicator.getProgram();
		if (program == null) {
			applicator.pdbLogAndErrorMessage(this,
				"Unable to retrieve Program header: program null", null);
			return;
		}

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		if (allFileBytes.isEmpty()) {
			applicator.pdbLogAndErrorMessage(this,
				"Unable to retrieve Program header: no FileBytes", null);
			return;
		}
		FileBytes fileBytes = allFileBytes.get(0); // Should be that of main imported file
		ByteProvider provider = new FileBytesProvider(fileBytes); // close not required
		try {
			PortableExecutable pe =
				new PortableExecutable(provider, SectionLayout.FILE, true, true);
			NTHeader ntHeader = pe.getNTHeader(); // will be null if header parse fails
			if (ntHeader == null) {
				applicator.pdbLogAndErrorMessage(this, "Unable to retrieve NTHeader from PE", null);
				return;
			}
			OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
			originalImageBase = optionalHeader.getImageBase();
			int characteristics = ntHeader.getFileHeader().getCharacteristics();
			isDll = (characteristics & FileHeader.IMAGE_FILE_DLL) == FileHeader.IMAGE_FILE_DLL;
			DataDirectory[] dataDirectory = optionalHeader.getDataDirectories();
			int optionalHeaderCharaceristics = optionalHeader.getDllCharacteristics();
			isAslr = (optionalHeaderCharaceristics &
				OptionalHeader.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) == OptionalHeader.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
			if (OptionalHeader.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR >= dataDirectory.length) {
				applicator.pdbLogAndErrorMessage(this,
					"Bad index (" + OptionalHeader.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR +
						") for COMDescriptorDataDirectory in DataDirectory array of size " +
						dataDirectory.length,
					null);
				return;
			}
			COMDescriptorDataDirectory comDir =
				(COMDescriptorDataDirectory) dataDirectory[OptionalHeader.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
			ImageCor20Header header = comDir.getHeader();
			if (header == null) {
				applicator.pdbLogAndErrorMessage(this, "COMDir header not available", null);
				return;
			}
			metadataStream = header.getMetadata().getMetadataRoot().getMetadataStream();
		}
		catch (RuntimeException | IOException e) {
			// We do not know what can go wrong.  Some of the header parsing might have issues,
			// and we'd rather log the error and limp on by with whatever other processing we can
			// do than to fail here.
			applicator.pdbLogAndErrorMessage(this,
				"Unable to retrieve program header information: " + e.getMessage(), e);
			return;
		}
	}
}
