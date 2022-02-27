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

import java.util.Collection;
import java.util.Map.Entry;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class ReadsTargetMemoryPcodeExecutorState
		extends AbstractReadsTargetPcodeExecutorState {

	protected class ReadsTargetMemoryCachedSpace extends AbstractReadsTargetCachedSpace {

		public ReadsTargetMemoryCachedSpace(Language language, AddressSpace space,
				TraceMemorySpace source, long snap) {
			super(language, space, source, snap);
		}

		@Override
		protected void fillUninitialized(AddressSet uninitialized) {
			AddressSet unknown;
			unknown = computeUnknown(uninitialized);
			if (unknown.isEmpty()) {
				return;
			}
			if (fillUnknownWithRecorder(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
			if (fillUnknownWithStaticImages(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
		}

		protected boolean fillUnknownWithRecorder(AddressSet unknown) {
			if (!isLive()) {
				return false;
			}
			waitTimeout(recorder.captureProcessMemory(unknown, TaskMonitor.DUMMY, false));
			return true;
		}

		private boolean fillUnknownWithStaticImages(AddressSet unknown) {
			boolean result = false;
			// TODO: Expand to block? DON'T OVERWRITE KNOWN!
			DebuggerStaticMappingService mappingService =
				tool.getService(DebuggerStaticMappingService.class);
			byte[] data = new byte[4096];
			for (Entry<Program, Collection<MappedAddressRange>> ent : mappingService
					.getOpenMappedViews(trace, unknown, snap)
					.entrySet()) {
				Program program = ent.getKey();
				Memory memory = program.getMemory();
				AddressSetView initialized = memory.getLoadedAndInitializedAddressSet();

				Collection<MappedAddressRange> mappedSet = ent.getValue();
				for (MappedAddressRange mappedRng : mappedSet) {
					AddressRange srng = mappedRng.getSourceAddressRange();
					long shift = mappedRng.getShift();
					for (AddressRange subsrng : initialized.intersectRange(srng.getMinAddress(),
						srng.getMaxAddress())) {
						Msg.debug(this,
							"Filling in unknown trace memory in emulator using mapped image: " +
								program + ": " + subsrng);
						long lower = subsrng.getMinAddress().getOffset();
						long fullLen = subsrng.getLength();
						while (fullLen > 0) {
							int len = MathUtilities.unsignedMin(data.length, fullLen);
							try {
								int read =
									memory.getBytes(space.getAddress(lower), data, 0, len);
								if (read < len) {
									Msg.warn(this,
										"  Partial read of " + subsrng + ". Got " + read +
											" bytes");
								}
								// write(lower - shift, data, 0 ,read);
								cache.putData(lower - shift, data, 0, read);
							}
							catch (MemoryAccessException | AddressOutOfBoundsException e) {
								throw new AssertionError(e);
							}
							lower += len;
							fullLen -= len;
						}
						result = true;
					}
				}
			}
			return result;
		}
	}

	public ReadsTargetMemoryPcodeExecutorState(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(tool, trace, snap, thread, frame, recorder);
	}

	@Override
	protected AbstractReadsTargetCachedSpace createCachedSpace(AddressSpace s,
			TraceMemorySpace tms) {
		return new ReadsTargetMemoryCachedSpace(language, s, tms, snap);
	}
}
