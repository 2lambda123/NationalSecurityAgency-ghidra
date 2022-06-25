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
package ghidra.file.formats.android.oat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.oat.bundle.OatBundle;
import ghidra.file.formats.android.oat.bundle.OatBundleFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class OatHeaderFactory {

	/**
	 * Returns an OatHeader of the correct version.
	 * @param reader the binary reader for the OAT header
	 * @return the new OAT header
	 * @throws IOException if OAT header cannot be created from reader
	 * @throws UnsupportedOatVersionException when the provided version is invalid or not yet implemented.
	 */
	public final static OatHeader newOatHeader(BinaryReader reader)
			throws IOException, UnsupportedOatVersionException {
		String magic = new String(reader.readByteArray(0, OatConstants.MAGIC.length()));
		String version = reader.readAsciiString(4, 4);
		if (magic.equals(OatConstants.MAGIC)) {
			if (OatConstants.isSupportedVersion(version)) {
				switch (version) {
					case OatConstants.VERSION_KITKAT_RELEASE:
						return new OatHeader_KitKat(reader);
					case OatConstants.VERSION_LOLLIPOP_RELEASE:
					case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
					case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
						return new OatHeader_Lollipop(reader);
					case OatConstants.VERSION_MARSHMALLOW_RELEASE:
						return new OatHeader_Marshmallow(reader);
					case OatConstants.VERSION_NOUGAT_RELEASE:
					case OatConstants.VERSION_NOUGAT_MR1_RELEASE:
						return new OatHeader_Nougat(reader);
					case OatConstants.VERSION_OREO_RELEASE:
					case OatConstants.VERSION_OREO_DR3_RELEASE:
						return new OatHeader_Oreo(reader);//v124 and v126 are same format
					case OatConstants.VERSION_OREO_M2_RELEASE:
						return new OatHeader_Oreo_M2(reader);
					case OatConstants.VERSION_PIE_RELEASE:
						return new OatHeader_Pie(reader);
					case OatConstants.VERSION_10_RELEASE:
						return new OatHeader_10(reader);
					case OatConstants.VERSION_11_RELEASE:
						return new OatHeader_11(reader);
					case OatConstants.VERSION_12_RELEASE:
					case OatConstants.VERSION_S_V2_PREVIEW:
						return new OatHeader_12(reader);
				}
			}
		}
		throw new UnsupportedOatVersionException(magic, version);
	}

	public final static void parseOatHeader(OatHeader oatHeader, Program oatProgram,
			BinaryReader reader, TaskMonitor monitor, MessageLog log)
			throws UnsupportedOatVersionException, IOException {

		OatBundle bundle = OatBundleFactory.getOatBundle(oatProgram, oatHeader, monitor, log);
		oatHeader.parse(reader, bundle);
		bundle.close();
	}

}
