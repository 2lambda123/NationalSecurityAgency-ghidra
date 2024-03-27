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
package ghidra.pty.local;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.pty.PtySession;
import ghidra.util.Msg;

/**
 * A pty session consisting of a local process and its descendants
 */
public class LocalProcessPtySession implements PtySession {
	private final Process process;
	private final String ptyName;

	public LocalProcessPtySession(Process process, String ptyName) {
		this.process = process;
		this.ptyName = ptyName;
		Msg.info(this, "local Pty session. PID = " + process.pid());
	}

	@Override
	public int waitExited() throws InterruptedException {
		return process.waitFor();
	}

	@Override
	public int waitExited(long timeout, TimeUnit unit)
			throws InterruptedException, TimeoutException {
		if (!process.waitFor(timeout, unit)) {
			throw new TimeoutException();
		}
		return process.exitValue();
	}

	@Override
	public void destroyForcibly() {
		process.destroyForcibly();
	}

	@Override
	public String description() {
		return "process " + process.pid() + " on " + ptyName;
	}
}
