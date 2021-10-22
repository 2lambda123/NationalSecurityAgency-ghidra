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
package mdemangler;

/**
 * A class to handle exceptions that occur demangling for MDMang and
 * related derived and subordinate classes.
 */
public class MDException extends Exception {
	private boolean invalidMangledName;
	private static final long serialVersionUID = 0;

	/**
	 * Use this constructor to indicate a demangler exception
	 * due to an exception thrown during the demangling process.
	 * @param cause the exception thrown during the demangling process
	 */
	public MDException(Exception cause) {
		super(cause);
	}

	/**
	 * Use this constructor to indicate a demangler exception
	 * due to some general invalid or unsupported mangled string
	 * characteristic. For example, unrecognized datatype.
	 * @param message the invalid or unsupported mangled message
	 */
	public MDException(String message) {
		super(message);
	}

	/**
	 * Use this constructor to indicate the demangler failed
	 * because the string to demangle does not appear to represent
	 * a valid mangled name.
	 * @param invalidMangledName true to indicate the string to
	 * demangle does not appear to represent a valid mangled name
	 */
	public MDException(boolean invalidMangledName) {
		this.invalidMangledName = invalidMangledName;
	}

	/**
	 * Returns true if the string to demangle does not appear to represent
	 * a valid mangled name
	 * @return true if the string to demangle does not appear to represent
	 * a valid mangled name
	 */
	public boolean isInvalidMangledName() {
		return invalidMangledName;
	}
}
