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
package ghidra.file.formats.android.bootimg;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;

/**
 * Base class to represent a Vendor Boot Image header.
 */
public abstract class VendorBootImageHeader implements StructConverter {

	public abstract String getMagic();

	public abstract long getVendorRamdiskOffset();

	public abstract int getVendorRamdiskSize();

	public abstract long getDtbOffset();

	public abstract int getDtbSize();

	public long getNestedVendorRamdiskCount() {
		return 1;
	}

	public long getNestedVendorRamdiskOffset(int index) throws IOException {
		return getVendorRamdiskOffset();
	}

	public int getNestedVendorRamdiskSize(int index) throws IOException {
		return getVendorRamdiskSize();
	}

}
