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
package ghidra.file.formats.ios.img2;

import java.util.Arrays;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Img2FileSystemFactory implements GFileSystemFactoryByteProvider<Img2FileSystem>, GFileSystemProbeBytesOnly {

	@Override
	public int getBytesRequired() {
		return Img2Constants.IMG2_SIGNATURE_BYTES.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return Arrays.equals(startBytes, 0, Img2Constants.IMG2_SIGNATURE_BYTES.length,
			Img2Constants.IMG2_SIGNATURE_BYTES, 0, Img2Constants.IMG2_SIGNATURE_BYTES.length);
	}

	@Override
	public Img2FileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		return new Img2FileSystem(targetFSRL, byteProvider, monitor);
	}

}
