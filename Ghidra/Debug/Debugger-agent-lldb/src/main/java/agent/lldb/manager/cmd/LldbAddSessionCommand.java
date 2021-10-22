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
package agent.lldb.manager.cmd;

import SWIG.SBTarget;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbManager#addSession()}
 */
public class LldbAddSessionCommand extends AbstractLldbCommand<SBTarget> {

	public LldbAddSessionCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public SBTarget complete(LldbPendingCommand<?> pending) {
		// Not apparent this is needed
		return null;
	}

}
