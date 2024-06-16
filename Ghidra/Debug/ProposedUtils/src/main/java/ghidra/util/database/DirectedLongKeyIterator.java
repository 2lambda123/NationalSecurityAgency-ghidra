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
package ghidra.util.database;

import java.io.IOException;

import db.Table;

/**
 * An iterator over keys of a table
 */
public interface DirectedLongKeyIterator extends DirectedIterator<Long> {
	/**
	 * Get an iterator over the table, restricted to the given range, in the given direction
	 * 
	 * @param table the table
	 * @param keySpan the limited range
	 * @param direction the direction
	 * @return the iterator
	 * @throws IOException if the table cannot be read
	 */
	public static AbstractDirectedLongKeyIterator getIterator(Table table, KeySpan keySpan,
			Direction direction) throws IOException {
		long min = keySpan.min();
		long max = keySpan.max();
		if (direction == Direction.FORWARD) {
			return new ForwardLongKeyIterator(table.longKeyIterator(min, max, min));
		}
		return new BackwardLongKeyIterator(table.longKeyIterator(min, max, max));
	}
}
