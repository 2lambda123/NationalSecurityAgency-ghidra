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
package agent.dbgmodel.model.invm;

import agent.dbgeng.dbgeng.DbgEngTest;
import agent.dbgeng.model.AbstractDbgengModelHost;
import agent.dbgmodel.DbgModelInJvmDebuggerModelFactory;
import ghidra.dbg.DebuggerModelFactory;

public class InVmDbgmodelModelHost extends AbstractDbgengModelHost {
	@Override
	public DebuggerModelFactory getModelFactory() {
		DbgEngTest.assumeDbgengDLLLoadable();
		return new DbgModelInJvmDebuggerModelFactory();
	}
}
