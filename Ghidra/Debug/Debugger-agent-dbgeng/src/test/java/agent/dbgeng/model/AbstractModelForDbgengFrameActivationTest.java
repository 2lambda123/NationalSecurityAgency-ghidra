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
package agent.dbgeng.model;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelActivationTest;
import ghidra.dbg.util.PathPattern;

public abstract class AbstractModelForDbgengFrameActivationTest
		extends AbstractDebuggerModelActivationTest {

	protected abstract PathPattern getStackPattern();

	protected DebuggerTestSpecimen getSpecimen() {
		return WindowsSpecimen.STACK;
	}

	@Override
	protected Set<TargetObject> getActivatableThings() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		TargetLauncher launcher = findLauncher(); // root launcher should generate new inferiors
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		TargetProcess process = retry(() -> {
			TargetProcess p = m.findAny(TargetProcess.class, seedPath());
			assertNotNull(p);
			return p;
		}, List.of(AssertionError.class));

		trapAt("expStack!break_here", process);

		waitSettled(m.getModel(), 200);

		return retry(() -> {
			Map<List<String>, TargetStackFrame> frames =
				m.findAll(TargetStackFrame.class, seedPath(), true);
			assertTrue(frames.size() >= 3);
			return Set.copyOf(frames.values());
		}, List.of(AssertionError.class));
	}

	// TODO: Should probably assert default focus/activation here

	@Override
	@Ignore("dbgeng.dll has no event for frame activation")
	public void testActivateEachViaInterpreter() throws Throwable {
	}

	@Override
	protected void assertActiveViaInterpreter(TargetObject expected, TargetInterpreter interpreter)
			throws Throwable {
		String line = waitOn(interpreter.executeCapture(".frame")).trim();
		assertFalse(line.contains("\n"));
		int frameId = Integer.parseInt(line.split("\\s+")[0], 16);
		int expId = Integer.decode(getStackPattern().matchIndices(expected.getPath()).get(2));
		assertEquals(expId, frameId);
	}

	@Override
	@Test
	public void testActivateEachOnce() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
		}

	}

	@Test
	public void testActivateEachTwice() throws Throwable {
		m.build();

		TargetActiveScope activeScope = findActiveScope();
		Set<TargetObject> activatable = getActivatableThings();
		for (TargetObject obj : activatable) {
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
			waitOn(activeScope.requestActivation(obj));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertActiveViaInterpreter(obj, interpreter);
			}
		}
	}

}
