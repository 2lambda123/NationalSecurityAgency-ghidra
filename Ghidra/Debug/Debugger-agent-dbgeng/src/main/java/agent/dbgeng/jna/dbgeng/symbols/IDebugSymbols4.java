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
package agent.dbgeng.jna.dbgeng.symbols;

import com.sun.jna.platform.win32.Guid.IID;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSymbols4 extends IDebugSymbols3 {
	final IID IID_IDEBUG_SYMBOLS4 = new IID("e391bbd8-9d8c-4418-840b-c006592a1752");

	enum VTIndices4 implements VTableIndex {
		GET_SCOPE_EX, //
		SET_SCOPE_EX, //
		GET_NAME_BY_INLINE_CONTEXT, //
		GET_NAME_BY_INLINE_CONTEXT_WIDE, //
		GET_LINE_BY_INLINE_CONTEXT, //
		GET_LINE_BY_INLINE_CONTEXT_WIDE, //
		OUTPUT_SYMBOL_BY_INLINE_CONTEXT, //
		;

		static int start = VTableIndex.follow(VTIndices3.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}
}
