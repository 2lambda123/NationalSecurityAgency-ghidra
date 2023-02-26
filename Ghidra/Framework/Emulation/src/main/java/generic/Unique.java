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
package generic;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Some utilities for when singleton collections are expected
 */
public interface Unique {

	static <T> T assertAtMostOne(T[] arr) {
		if (arr.length == 0) {
			return null;
		}
		if (arr.length == 1) {
			return arr[0];
		}
		throw new AssertionError("Expected at most one. Got many: " + List.of(arr));
	}

	/**
	 * Assert that exactly one element is in an iterable and get that element
	 * 
	 * @param <T> the type of element
	 * @param col the iterable
	 * @return the element
	 * @throws AssertionError if no element or many elements exist in the iterable
	 */
	static <T> T assertOne(Iterable<T> col) {
		Iterator<T> it = col.iterator();
		if (!it.hasNext()) {
			throw new AssertionError("Expected exactly one. Got none.");
		}
		T result = it.next();
		if (it.hasNext()) {
			List<T> all = new ArrayList<>();
			all.add(result);
			while (it.hasNext()) {
				all.add(it.next());
			}
			throw new AssertionError("Expected exactly one. Got many: " + all);
		}
		return result;
	}

	/**
	 * Assert that exactly one element is in a stream and get that element
	 * 
	 * @param <T> the type of element
	 * @param st the stream
	 * @return the element
	 * @throws AssertionError if no element or many elements exist in the stream
	 */
	static <T> T assertOne(Stream<T> st) {
		return assertOne(st.collect(Collectors.toList()));
	}

	/**
	 * Assert that at most one element is in an iterable and get that element or {@code null}
	 * 
	 * @param <T> the type of element
	 * @param col the iterable
	 * @return the element or {@code null} if empty
	 * @throws AssertionError if many elements exist in the iterable
	 */
	static <T> T assertAtMostOne(Iterable<T> col) {
		Iterator<T> it = col.iterator();
		if (!it.hasNext()) {
			return null;
		}
		T result = it.next();
		if (it.hasNext()) {
			throw new AssertionError("Expected at most one. Got many.");
		}
		return result;
	}
}
