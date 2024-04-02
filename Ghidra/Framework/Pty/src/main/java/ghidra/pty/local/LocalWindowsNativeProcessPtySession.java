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

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.ptr.IntByReference;

import ghidra.pty.PtySession;
import ghidra.pty.windows.Handle;
import ghidra.util.Msg;

public class LocalWindowsNativeProcessPtySession implements PtySession {
	private final int pid;
	//private final int tid;
	private final Handle processHandle;
	//private final Handle threadHandle;
	private final String ptyName;

	public LocalWindowsNativeProcessPtySession(int pid, int tid, Handle processHandle,
			Handle threadHandle, String ptyName) {
		this.pid = pid;
		//this.tid = tid;
		this.processHandle = processHandle;
		//this.threadHandle = threadHandle;
		this.ptyName = ptyName;

		Msg.info(this, "local Windows Pty session. PID = " + pid);
	}

	protected int doWaitExited(int millis) throws TimeoutException {
		while (true) {
			switch (Kernel32.INSTANCE.WaitForSingleObject(processHandle.getNative(), millis)) {
				case Kernel32.WAIT_OBJECT_0:
				case Kernel32.WAIT_ABANDONED:
					IntByReference lpExitCode = new IntByReference();
					Kernel32.INSTANCE.GetExitCodeProcess(processHandle.getNative(), lpExitCode);
					if (lpExitCode.getValue() != WinBase.STILL_ACTIVE) {
						return lpExitCode.getValue();
					}
				case Kernel32.WAIT_TIMEOUT:
					throw new TimeoutException();
				case Kernel32.WAIT_FAILED:
					throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
			}
		}
	}

	@Override
	public int waitExited() {
		try {
			return doWaitExited(-1);
		}
		catch (TimeoutException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public int waitExited(long timeout, TimeUnit unit) throws TimeoutException {
		long millis = TimeUnit.MILLISECONDS.convert(timeout, unit);
		if (millis > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("Too long a timeout");
		}
		return doWaitExited((int) millis);
	}

	@Override
	public void destroyForcibly() {
		if (!Kernel32.INSTANCE.TerminateProcess(processHandle.getNative(), 1)) {
			int error = Kernel32.INSTANCE.GetLastError();
			switch (error) {
				case Kernel32.ERROR_ACCESS_DENIED:
					/**
					 * This indicates the process has already terminated. It's unclear to me whether
					 * or not that is the only possible cause of this error.
					 */
					return;
			}
			throw new LastErrorException(error);
		}
	}

	@Override
	public String description() {
		return "process " + pid + " on " + ptyName;
	}
}
