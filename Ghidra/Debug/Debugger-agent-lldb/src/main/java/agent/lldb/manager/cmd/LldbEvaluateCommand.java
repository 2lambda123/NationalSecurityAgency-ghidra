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

import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#evaluate(String)}
 */
public class LldbEvaluateCommand extends AbstractLldbCommand<String> {
	private final String expression;
	private String result;

	public LldbEvaluateCommand(LldbManagerImpl manager, String expression) {
		super(manager);
		this.expression = expression;
	}

	@Override
	public String complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		manager.getClient().execute(expression);
	}
}
