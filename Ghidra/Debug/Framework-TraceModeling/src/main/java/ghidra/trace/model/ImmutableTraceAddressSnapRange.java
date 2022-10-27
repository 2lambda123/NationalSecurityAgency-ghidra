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
package ghidra.trace.model;

import ghidra.program.model.address.*;
import ghidra.util.database.spatial.rect.EuclideanSpace2D;

public class ImmutableTraceAddressSnapRange implements TraceAddressSnapRange {
	public static AddressRange rangeCentered(Address address, int breadth) {
		AddressSpace space = address.getAddressSpace();
		Address min = Long.compareUnsigned(address.subtract(space.getMinAddress()), breadth) <= 0
				? space.getMinAddress()
				: address.subtract(breadth);
		Address max = Long.compareUnsigned(space.getMaxAddress().subtract(address), breadth) <= 0
				? space.getMaxAddress()
				: address.add(breadth);
		return new AddressRangeImpl(min, max);
	}

	public static Lifespan spanCentered(long snap, int breadth) {
		long min = Long.compareUnsigned(snap - Long.MIN_VALUE, breadth) <= 0
				? Long.MIN_VALUE
				: snap - breadth;
		long max = Long.compareUnsigned(Long.MAX_VALUE - snap, breadth) <= 0
				? Long.MAX_VALUE
				: snap + breadth;
		return Lifespan.span(min, max);
	}

	public static ImmutableTraceAddressSnapRange centered(Address address, long snap,
			int addressBreadth, int snapBreadth) {
		return new ImmutableTraceAddressSnapRange(rangeCentered(address, addressBreadth),
			spanCentered(snap, snapBreadth));
	}

	protected final AddressRange range;
	protected final Lifespan lifespan;
	protected final EuclideanSpace2D<Address, Long> space;

	public ImmutableTraceAddressSnapRange(Address minAddress, Address maxAddress, long minSnap,
			long maxSnap, TraceAddressSnapSpace space) {
		this.range = new AddressRangeImpl(minAddress, maxAddress);
		this.lifespan = Lifespan.span(minSnap, maxSnap);
		this.space = space;
	}

	public ImmutableTraceAddressSnapRange(Address minAddress, Address maxAddress, long minSnap,
			long maxSnap) {
		this.range = new AddressRangeImpl(minAddress, maxAddress);
		this.lifespan = Lifespan.span(minSnap, maxSnap);
		this.space = TraceAddressSnapSpace.forAddressSpace(minAddress.getAddressSpace());
	}

	public ImmutableTraceAddressSnapRange(AddressRange range, Lifespan lifespan) {
		this.range = range;
		this.lifespan = lifespan;
		this.space = TraceAddressSnapSpace.forAddressSpace(range.getAddressSpace());
	}

	public ImmutableTraceAddressSnapRange(AddressRange range, long snap) {
		this.range = range;
		this.lifespan = Lifespan.at(snap);
		this.space = TraceAddressSnapSpace.forAddressSpace(range.getAddressSpace());
	}

	public ImmutableTraceAddressSnapRange(Address minAddress, Address maxAddress,
			Lifespan lifespan, EuclideanSpace2D<Address, Long> space) {
		this.range = new AddressRangeImpl(minAddress, maxAddress);
		this.lifespan = lifespan;
		this.space = space;
	}

	public ImmutableTraceAddressSnapRange(Address minAddress, Address maxAddress,
			Lifespan lifespan) {
		this.range = new AddressRangeImpl(minAddress, maxAddress);
		this.lifespan = lifespan;
		this.space = TraceAddressSnapSpace.forAddressSpace(range.getAddressSpace());
	}

	public ImmutableTraceAddressSnapRange(Address address, Lifespan lifespan) {
		this.range = new AddressRangeImpl(address, address);
		this.lifespan = lifespan;
		this.space = TraceAddressSnapSpace.forAddressSpace(address.getAddressSpace());
	}

	public ImmutableTraceAddressSnapRange(Address address, long snap) {
		this.range = new AddressRangeImpl(address, address);
		this.lifespan = Lifespan.at(snap);
		this.space = TraceAddressSnapSpace.forAddressSpace(address.getAddressSpace());
	}

	@Override
	public boolean equals(Object obj) {
		return doEquals(obj);
	}

	@Override
	public int hashCode() {
		return doHashCode();
	}

	@Override
	public String toString() {
		return description();
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	@Override
	public Lifespan getLifespan() {
		return lifespan;
	}

	@Override
	public EuclideanSpace2D<Address, Long> getSpace() {
		return space;
	}
}
