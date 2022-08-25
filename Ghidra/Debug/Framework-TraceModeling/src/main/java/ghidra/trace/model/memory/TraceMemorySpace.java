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
package ghidra.trace.model.memory;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * A portion of the memory manager bound to a particular address space
 * 
 * <p>
 * For most memory operations, the methods on {@link TraceMemoryManager} are sufficient, as they
 * will automatically obtain the appropriate {@link TraceMemorySpace} for the address space of the
 * given address or range. If many operations on the same space are anticipated, it may be slightly
 * faster to bind to the space once and then perform all the operations. It is also necessary to
 * bind when operating on (per-thread) register spaces
 */
public interface TraceMemorySpace extends TraceMemoryOperations {
	/**
	 * Get the address space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();

	/**
	 * Get the code space for this memory space
	 * 
	 * <p>
	 * This is a convenience for {@link TraceCodeManager#getCodeSpace(AddressSpace, boolean) on this
	 * same address space.
	 * 
	 * @return the code space
	 */
	TraceCodeSpace getCodeSpace(boolean createIfAbsent);

	/**
	 * Get the thread for this register space
	 * 
	 * @return the thread
	 */
	TraceThread getThread();

	/**
	 * Get the registers
	 * 
	 * <p>
	 * This is a convenience for {@code getTrace().getBaseLanguage().getRegisters()}
	 * 
	 * @return the list of registers
	 */
	default List<Register> getRegisters() {
		return getTrace().getBaseLanguage().getRegisters();
	}

	/**
	 * Set the state of a given register at a given time
	 * 
	 * <p>
	 * Setting state to {@link TraceMemoryState#KNOWN} via this method is not recommended. Setting
	 * bytes will automatically update the state accordingly.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @param state the state
	 */
	default void setState(long snap, Register register, TraceMemoryState state) {
		setState(snap, TraceRegisterUtils.rangeForRegister(register), state);
	}

	/**
	 * Assert that a register's range has a single state at the given snap and get that state
	 * 
	 * @param snap the time
	 * @param register the register to examine
	 * @return the state
	 * @throws IllegalStateException if the register is mapped to more than one state. See
	 *             {@link #getStates(long, Register)}
	 */
	default TraceMemoryState getState(long snap, Register register) {
		Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> states =
			getStates(snap, register);
		if (states.isEmpty()) {
			return TraceMemoryState.UNKNOWN;
		}
		if (states.size() != 1) {
			throw new IllegalStateException("More than one state is present in " + register);
		}
		return states.iterator().next().getValue();
	}

	/**
	 * Break the register's range into smaller ranges each mapped to its state at the given snap
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register to examine
	 * @return the map of ranges to states
	 */
	default Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStates(long snap,
			Register register) {
		AddressRange range = TraceRegisterUtils.rangeForRegister(register);
		if (register.getAddressSpace() != getAddressSpace()) {
			return getTrace().getMemoryManager().getStates(snap, range);
		}
		return getStates(snap, range);
	}

	/**
	 * Set the value of a register at the given snap
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * <p>
	 * <b>IMPORTANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given value specifies, e.g.,
	 * only a single bit, then the entire byte will become marked {@link TraceMemoryState#KNOWN},
	 * even though the remaining 7 bits could technically be unknown.
	 * 
	 * @param snap the snap
	 * @param value the register value
	 * @return the number of bytes written
	 */
	default int setValue(long snap, RegisterValue value) {
		if (!value.hasAnyValue()) {
			return 0;
		}
		Register reg = value.getRegister();
		if (!value.hasValue() || !TraceRegisterUtils.isByteBound(reg)) {
			RegisterValue old = getValue(snap, reg.getBaseRegister());
			// Do not use .getRegisterValue, as that will zero unmasked bits
			// Instead, we'll pass the original register to bufferForValue
			value = old.combineValues(value);
		}
		ByteBuffer buf = TraceRegisterUtils.bufferForValue(reg, value);
		// TODO: A better way to deal with memory-mapped registers?
		if (reg.getAddressSpace() != getAddressSpace()) {
			return getTrace().getMemoryManager().putBytes(snap, reg.getAddress(), buf);
		}
		return putBytes(snap, reg.getAddress(), buf);
	}

	/**
	 * Write bytes at the given snap and register address
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * <p>
	 * Note that bit-masked registers are not properly heeded. If the caller wishes to preserve
	 * non-masked bits, it must first retrieve the current value and combine it with the desired
	 * value. The caller must also account for any bit shift in the passed buffer. Alternatively,
	 * consider {@link #setValue(long, RegisterValue)}.
	 * 
	 * @param snap the snap
	 * @param register the register to modify
	 * @param buf the buffer of bytes to write
	 * @return the number of bytes written
	 */
	default int putBytes(long snap, Register register, ByteBuffer buf) {
		int byteLength = register.getNumBytes();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		// TODO: A better way to deal with memory-mapped registers?
		int result;
		if (register.getAddressSpace() != getAddressSpace()) {
			result = getTrace().getMemoryManager().putBytes(snap, register.getAddress(), buf);
		}
		else {
			result = putBytes(snap, register.getAddress(), buf);
		}
		buf.limit(limit);
		return result;
	}

	/**
	 * Get the most-recent value of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	default RegisterValue getValue(long snap, Register register) {
		return TraceRegisterUtils.getRegisterValue(register, (a, buf) -> {
			// TODO: A better way to deal with memory-mapped registers?
			if (a.getAddressSpace() != getAddressSpace()) {
				getTrace().getMemoryManager().getBytes(snap, a, buf);
			}
			else {
				getBytes(snap, a, buf);
			}
		});
	}

	/**
	 * Get the most-recent value of a given register at the given time, following schedule forks
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @return the value
	 */
	default RegisterValue getViewValue(long snap, Register register) {
		return TraceRegisterUtils.getRegisterValue(register, (a, buf) -> {
			// TODO: A better way to deal with memory-mapped registers?
			if (a.getAddressSpace() != getAddressSpace()) {
				getTrace().getMemoryManager().getViewBytes(snap, a, buf);
			}
			else {
				getViewBytes(snap, a, buf);
			}
		});
	}

	/**
	 * Get the most-recent bytes of a given register at the given time
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * @param snap the time
	 * @param register the register
	 * @param buf the destination buffer
	 * @return the number of bytes read
	 */
	default int getBytes(long snap, Register register, ByteBuffer buf) {
		int byteLength = register.getNumBytes();
		int limit = buf.limit();
		buf.limit(Math.min(limit, buf.position() + byteLength));
		// TODO: A better way to deal with memory-mapped registers?
		int result;
		if (register.getAddressSpace() != getAddressSpace()) {
			result = getTrace().getMemoryManager().getBytes(snap, register.getAddress(), buf);
		}
		else {
			result = getBytes(snap, register.getAddress(), buf);
		}
		buf.limit(limit);
		return result;
	}

	/**
	 * Remove a value from the given time and register
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space.
	 * 
	 * <p>
	 * <b>IMPORANT:</b> The trace database cannot track the state ({@link TraceMemoryState#KNOWN},
	 * etc.) with per-bit accuracy. It only has byte precision. If the given register specifies,
	 * e.g., only a single bit, then the entire byte will become marked
	 * {@link TraceMemoryState#UNKNOWN}, even though the remaining 7 bits could technically be
	 * known.
	 * 
	 * @param snap the snap
	 * @param register the register
	 */
	default void removeValue(long snap, Register register) {
		int byteLength = register.getNumBytes();
		if (register.getAddressSpace() != getAddressSpace()) {
			getTrace().getMemoryManager().removeBytes(snap, register.getAddress(), byteLength);
		}
		else {
			removeBytes(snap, register.getAddress(), byteLength);
		}
	}

	/**
	 * Get the most recent values for all registers at the given time
	 * 
	 * @param snap the time
	 * @return all register values
	 */
	default Collection<RegisterValue> getAllValues(long snap) {
		Set<RegisterValue> result = new LinkedHashSet<>();
		for (Register reg : getRegisters()) {
			result.add(getValue(snap, reg));
		}
		return result;
	}
}
