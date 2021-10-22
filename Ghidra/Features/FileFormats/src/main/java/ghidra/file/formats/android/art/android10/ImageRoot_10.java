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
package ghidra.file.formats.android.art.android10;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/image.h
 */
public enum ImageRoot_10 {
	kDexCaches,
	kClassRoots,
	/** Pre-allocated OOME when throwing exception.*/
	kOomeWhenThrowingException,
	/** Pre-allocated OOME when throwing OOME. */
	kOomeWhenThrowingOome,
	/** Pre-allocated OOME when handling StackOverflowError. */
	kOomeWhenHandlingStackOverflow,
	/** Pre-allocated NoClassDefFoundError. */
	kNoClassDefFoundError,
	/** Different for boot image and app image, see aliases below. */
	kSpecialRoots,
	kImageRootsMax;

	//Aliases

	/** The class loader used to build the app image.*/
	public final static ImageRoot_10 kAppImageClassLoader = kSpecialRoots;

	/** Array of boot image objects that must be kept live. */
	public final static ImageRoot_10 kBootImageLiveObjects = kSpecialRoots;
}
