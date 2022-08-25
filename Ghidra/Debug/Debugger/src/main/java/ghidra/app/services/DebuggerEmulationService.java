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
package ghidra.app.services;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A service for accessing managed emulators.
 * 
 * <p>
 * Managed emulators are employed by the UI and trace manager to perform emulation requested by the
 * user. Scripts may interact with these managed emulators, or they may instantiate their own
 * unmanaged emulators, without using this service.
 */
@ServiceInfo(defaultProvider = DebuggerEmulationServicePlugin.class)
public interface DebuggerEmulationService {

	/**
	 * Get the available emulator factories
	 * 
	 * @return the collection of factories
	 */
	Collection<DebuggerPcodeEmulatorFactory> getEmulatorFactories();

	/**
	 * Set the current emulator factory
	 * 
	 * <p>
	 * TODO: Should this be set on a per-program, per-trace basis? Need to decide what is saved to
	 * the tool and what is saved to the program/trace. My inclination is to save current factory to
	 * the tool, but the config options for each factory to the program/trace.
	 * 
	 * <p>
	 * TODO: Should there be some opinion service for choosing default configs? Seem overly
	 * complicated for what it offers. For now, we won't save anything, we'll default to the
	 * (built-in) {@link BytesDebuggerPcodeEmulatorFactory}, and we won't have configuration
	 * options.
	 * 
	 * @param factory the chosen factory
	 */
	void setEmulatorFactory(DebuggerPcodeEmulatorFactory factory);

	/**
	 * Get the current emulator factory
	 * 
	 * @return the factory
	 */
	DebuggerPcodeEmulatorFactory getEmulatorFactory();

	/**
	 * Perform emulation to realize the machine state of the given time coordinates
	 * 
	 * <p>
	 * Only those address ranges actually modified during emulation are written into the scratch
	 * space. It is the responsibility of anyone reading from scratch space to retrieve state and/or
	 * annotations from the initial snap, when needed. The scratch snapshot is given the description
	 * "{@code emu:[time]}", where {@code [time]} is the given time parameter as a string.
	 * 
	 * <p>
	 * The service may use a cached emulator in order to realize the requested machine state. This
	 * is especially important to ensure that a user stepping forward does not incur ever increasing
	 * costs. On the other hand, the service should be careful to invalidate cached results when the
	 * recorded machine state in a trace changes.
	 * 
	 * @param trace the trace containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @param monitor a monitor for cancellation and progress reporting
	 * @return the snap in the trace's scratch space where the realized state is stored
	 * @throws CancelledException if the emulation is cancelled
	 */
	long emulate(Trace trace, TraceSchedule time, TaskMonitor monitor) throws CancelledException;

	/**
	 * Invoke {@link #emulate(Trace, TraceSchedule, TaskMonitor)} in the background
	 * 
	 * <p>
	 * This is the preferred means of performing emulation. Because the underlying emulator may
	 * request a <em>blocking</em> read from a target, it is important that
	 * {@link #emulate(Trace, TraceSchedule, TaskMonitor)} is <em>never</em> called by the Swing
	 * thread.
	 * 
	 * @param trace the trace containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @return a future which completes with the result of
	 *         {@link #emulate(Trace, TraceSchedule, TaskMonitor)}
	 */
	CompletableFuture<Long> backgroundEmulate(Trace trace, TraceSchedule time);

	/**
	 * The the cached emulator for the given trace and time
	 * 
	 * <p>
	 * To guarantee the emulator is present, call {@link #backgroundEmulate(Trace, TraceSchedule)}
	 * first.
	 * <p>
	 * <b>WARNING:</b> This emulator belongs to this service. Stepping it, or otherwise manipulating
	 * it without the service's knowledge can lead to unintended consequences.
	 * 
	 * @param trace the trace containing the initial state
	 * @param time the time coordinates, including initial snap, steps, and p-code steps
	 * @return the copied p-code frame
	 */
	DebuggerPcodeMachine<?> getCachedEmulator(Trace trace, TraceSchedule time);
}
