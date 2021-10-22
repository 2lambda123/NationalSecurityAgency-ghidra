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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostExtensability extends IUnknownEx {
	final IID IID_IDEBUG_HOST_EXTENSABILITY = new IID("3C2B24E1-11D0-4f86-8AE5-4DF166F73253");

	enum VTIndices implements VTableIndex {
		CREATE_FUNCTION_ALIAS, //
		DESTROY_FUNCTION_ALIAS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT CreateFunctionAlias(WString aliasName, Pointer functionObject);

	HRESULT DestroyFunctionAlias(WString aliasName);

}
