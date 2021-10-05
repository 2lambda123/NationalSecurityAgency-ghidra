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

import java.util.ArrayList;
import java.util.List;

import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbProcessCreatedEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#launch(String)}
 */
public class LldbLaunchProcessCommand extends AbstractLldbCommand<SBThread> {

	private LldbProcessCreatedEvent created = null;
	private boolean completed = false;
	private String fileName;
	private List<String> args;
	private List<String> envp;
	private List<String> pathsIO;
	private String wdir;
	private long flags;
	private boolean stopAtEntry;

	public LldbLaunchProcessCommand(LldbManagerImpl manager, String fileName, List<String> args) {
		this(manager, fileName, args, null, null, "", 0L, true);
	}

	public LldbLaunchProcessCommand(LldbManagerImpl manager, String fileName, List<String> args,
			List<String> envp,
			List<String> pathsIO, String workingDirectory, long flags, boolean stopAtEntry) {
		super(manager);
		this.fileName = fileName;
		this.args = args == null ? new ArrayList<>() : args;
		this.envp = envp == null ? new ArrayList<>() : envp;
		this.pathsIO = pathsIO;
		if (pathsIO == null) {
			this.pathsIO = new ArrayList<>();
			this.pathsIO.add("");
			this.pathsIO.add("");
			this.pathsIO.add("");
		}
		this.wdir = workingDirectory;
		this.flags = flags;
		this.stopAtEntry = stopAtEntry;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof LldbProcessCreatedEvent) {
			created = (LldbProcessCreatedEvent) evt;
		}
		return completed && (created != null);
	}

	@Override
	public SBThread complete(LldbPendingCommand<?> pending) {
		return manager.getEventThread();
	}

	@Override
	public void invoke() {
		DebugClient client = manager.getClient();
		//client.createProcess(client.getLocalServer(), fileName);
		client.createProcess(client.getLocalServer(), fileName, args, envp, pathsIO, wdir, flags,
			stopAtEntry);
	}
}
