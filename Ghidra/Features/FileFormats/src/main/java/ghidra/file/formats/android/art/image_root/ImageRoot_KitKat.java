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
package ghidra.file.formats.android.art.image_root;

/**
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/image.h#91">kitkat-release/runtime/image.h</a>
 */
public enum ImageRoot_KitKat {
	kResolutionMethod,
	kCalleeSaveMethod,
	kRefsOnlySaveMethod,
	kRefsAndArgsSaveMethod,
	kOatLocation,
	kDexCaches,
	kClassRoots,
	kImageRootsMax,
}
