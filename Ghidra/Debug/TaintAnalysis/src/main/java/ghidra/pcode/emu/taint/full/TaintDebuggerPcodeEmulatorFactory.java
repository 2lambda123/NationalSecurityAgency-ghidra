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
package ghidra.pcode.emu.taint.full;

import ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeEmulatorFactory;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;

/**
 * An emulator factory for making the {@link TaintDebuggerPcodeEmulator} discoverable to the UI
 * 
 * <p>
 * This is the final class to create a full Debugger-integrated emulator. This class is what makes
 * it appear in the menu of possible emulators the user may configure.
 */
public class TaintDebuggerPcodeEmulatorFactory implements DebuggerPcodeEmulatorFactory {

	@Override
	public String getTitle() {
		return "Taint Analyzer with Concrete Emulation";
	}

	@Override
	public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess data) {
		return new TaintDebuggerPcodeEmulator(data);
	}
}
