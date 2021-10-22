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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgSetFilterSecondChanceCmdCommand
		extends AbstractDbgCommand<Void> {

	private int index;
	private String cmd;

	public DbgSetFilterSecondChanceCmdCommand(DbgManagerImpl manager, int index,
			String cmd) {
		super(manager);
		this.index = index;
		this.cmd = cmd;
	}

	@Override
	public void invoke() {
		DebugControl control = manager.getControl();
		control.setExceptionFilterSecondCommand(index, cmd);
	}
}
