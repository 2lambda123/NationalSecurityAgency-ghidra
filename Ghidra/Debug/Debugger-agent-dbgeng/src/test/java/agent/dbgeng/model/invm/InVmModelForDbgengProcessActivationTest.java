/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.dbgeng.model.invm;

import java.util.List;

import org.junit.Ignore;

import agent.dbgeng.model.AbstractModelForDbgengProcessActivationTest;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;

@Ignore("deprecated")
public class InVmModelForDbgengProcessActivationTest
		extends AbstractModelForDbgengProcessActivationTest {

	@Override
	protected PathPattern getProcessPattern() {
		return new PathPattern(PathUtils.parse("Sessions[0].Processes[]"));
	}

	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgengModelHost();
	}

	@Override
	public List<String> getExpectedSessionPath() {
		return PathUtils.parse("Sessions[0]");
	}

	@Override
	public String getIdFromCapture(String line) {
		return line.split("\\s+")[1];
	}

}
