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
package ghidra.app.plugin.core.debug.service.emulation;

import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerMemoryAccess;
import ghidra.pcode.exec.trace.*;

/**
 * A state composing a single {@link RWTargetMemoryPcodeExecutorStatePiece}
 */
public class RWTargetMemoryPcodeExecutorState extends DefaultTracePcodeExecutorState<byte[]> {
	/**
	 * Create the state
	 * 
	 * @param data the trace-memory access shim
	 * @param mode whether to ever write the target
	 */
	public RWTargetMemoryPcodeExecutorState(PcodeDebuggerMemoryAccess data, Mode mode) {
		super(new RWTargetMemoryPcodeExecutorStatePiece(data, mode));
	}

	protected RWTargetMemoryPcodeExecutorState(
			TracePcodeExecutorStatePiece<byte[], byte[]> piece) {
		super(piece);
	}

	@Override
	public RWTargetMemoryPcodeExecutorState fork() {
		return new RWTargetMemoryPcodeExecutorState(piece.fork());
	}
}
