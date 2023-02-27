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
package ghidra.app.events;

import java.lang.ref.WeakReference;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * Plugin event class for notification of programs being created, opened, or closed.
 */
public class ProgramOpenedPluginEvent extends PluginEvent {

	static final String NAME = "Program Opened";

	private WeakReference<Program> programRef;

	/**
	 * Construct a new plugin event.
	 * @param source name of the plugin that created this event
	 * @param p the program associated with this event
	 */
	public ProgramOpenedPluginEvent(String source, Program p) {
		super(source, NAME);
		this.programRef = new WeakReference<Program>(p);
	}

	/**
	 * Returns the {@link Program} that has just been opened. This method
	 * can return null, but only if the program has been closed and is no longer in use which
	 * can't happen if the method is called during the original event notification.
	 * @return the {@link Program} that has just been analyzed for the first time.
	 */
	public Program getProgram() {
		return programRef.get();
	}

}
