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
package ghidra.generic.util.datastruct;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.ULongSpan;

public class SemisparseByteArrayTest {
	private static final String HELLO_WORLD = "Hello, World!";
	protected static final byte[] HW = HELLO_WORLD.getBytes();

	protected static <T> Set<T> toSet(Iterable<T> it) {
		Set<T> result = new HashSet<>();
		for (T e : it) {
			result.add(e);
		}
		return result;
	}

	@Test
	public void testSingles() {
		SemisparseByteArray cache = new SemisparseByteArray();

		cache.putData(0, HW, 0, 1);
		assertEquals(Set.of(
			ULongSpan.span(0, 0)),
			toSet(cache.getInitialized(0, HW.length + 7).spans()));
		assertEquals(Set.of(
			ULongSpan.span(1, HW.length - 1)),
			toSet(cache.getUninitialized(0, HW.length - 1).spans()));

		cache.putData(2, HW, 2, 1);
		assertEquals(Set.of(
			ULongSpan.span(1, 1),
			ULongSpan.span(3, HW.length - 1)),
			toSet(cache.getUninitialized(0, HW.length - 1).spans()));

		cache.putData(11, HW, 11, 2);
		byte[] read = new byte[HW.length + 5]; // 5 extra
		cache.getData(0, read, 2, HW.length - 1); // Intentionally miss the '!'
		// ..................(offset of 2)   H   e   l   l  o  ,     W  o  r  l   d   !  (5 extra - 2)
		byte[] expRead = new byte[] { 0, 0, 'H', 0, 'l', 0, 0, 0, 0, 0, 0, 0, 0, 'd', 0, 0, 0, 0 };
		assertTrue(Arrays.equals(expRead, read));
	}

	@Test
	public void testBoundary() {
		SemisparseByteArray cache = new SemisparseByteArray();

		cache.putData(SemisparseByteArray.BLOCK_SIZE - 6, HW);
		byte[] data = new byte[HW.length];
		cache.getData(SemisparseByteArray.BLOCK_SIZE - 6, data);
		assertEquals(HELLO_WORLD, new String(data));
	}

	@Test
	public void testBoundaryAtSignedOverflow() {
		SemisparseByteArray cache = new SemisparseByteArray();

		cache.putData(0x7ffffffffffffff8L, HW);
		byte[] data = new byte[HW.length];
		cache.getData(0x7ffffffffffffff8L, data);
		assertEquals(HELLO_WORLD, new String(data));
	}

	@Test
	public void testBoundaryAtUnsignedMax() {
		SemisparseByteArray cache = new SemisparseByteArray();

		cache.putData(-HW.length, HW);
		byte[] data = new byte[HW.length];
		cache.getData(-HW.length, data);
		assertEquals(HELLO_WORLD, new String(data));
	}

	@Test
	public void testLarge() {
		Random rand = new Random();
		byte[] chunk = new byte[SemisparseByteArray.BLOCK_SIZE * 10];
		rand.nextBytes(chunk);

		SemisparseByteArray cache = new SemisparseByteArray();
		cache.putData(191, chunk);
		cache.putData(191 + chunk.length, HW);
		byte[] read = new byte[1 + chunk.length + HW.length];
		cache.getData(191, read, 1, chunk.length);

		assertEquals(0, read[0]); // Test the offset of 1
		for (int i = 0; i < chunk.length; i++) {
			assertEquals(chunk[i], read[1 + i]); // Test the actual copy
		}
		for (int i = 0; i < HW.length; i++) {
			assertEquals(0, read[1 + chunk.length + i]); // Test length param. Should not see HW.
		}
	}

	@Test
	public void testPutAll() {
		SemisparseByteArray first = new SemisparseByteArray();
		SemisparseByteArray second = new SemisparseByteArray();

		second.putData(0, new byte[] { 1, 2, 3, 4 });
		second.putData(-HW.length, HW);

		first.putData(2, new byte[] { 1, 2, 3, 4 });
		first.putData(-HW.length - 1, new byte[] { 10, 11 });

		first.putAll(second);

		assertEquals(Set.of(
			ULongSpan.span(0, 5),
			ULongSpan.span(-HW.length - 1, -1)),
			toSet(first.getInitialized(0, -1).spans()));

		byte[] read = new byte[6];
		first.getData(0, read);
		assertArrayEquals(new byte[] { 1, 2, 3, 4, 3, 4 }, read);

		read = new byte[HW.length];
		first.getData(-HW.length, read);
		assertArrayEquals(HW, read);

		read = new byte[2];
		first.getData(-HW.length - 1, read);
		assertArrayEquals(new byte[] { 10, 'H' }, read);
	}
}
