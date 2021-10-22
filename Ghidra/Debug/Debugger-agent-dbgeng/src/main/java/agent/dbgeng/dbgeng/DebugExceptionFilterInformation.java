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
package agent.dbgeng.dbgeng;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_EXCEPTION_FILTER_PARAMETERS;

public class DebugExceptionFilterInformation {

	private int nParams;
	private DEBUG_EXCEPTION_FILTER_PARAMETERS[] parameters;

	public DebugExceptionFilterInformation(int nParams,
			DEBUG_EXCEPTION_FILTER_PARAMETERS[] parameters) {
		this.nParams = nParams;
		this.parameters = parameters;
	}

	public int getNumberOfParameters() {
		return nParams;
	}

	public DEBUG_EXCEPTION_FILTER_PARAMETERS getParameter(int paramNumber) {
		return parameters[paramNumber];
	}

	public DEBUG_EXCEPTION_FILTER_PARAMETERS[] getParameters() {
		return parameters;
	}
}
