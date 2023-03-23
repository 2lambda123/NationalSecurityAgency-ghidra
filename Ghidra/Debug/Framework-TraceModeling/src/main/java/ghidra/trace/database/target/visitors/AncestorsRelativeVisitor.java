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
package ghidra.trace.database.target.visitors;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import ghidra.dbg.util.PathPredicates;
import ghidra.trace.database.target.visitors.TreeTraversal.SpanIntersectingVisitor;
import ghidra.trace.database.target.visitors.TreeTraversal.VisitResult;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;

public class AncestorsRelativeVisitor implements SpanIntersectingVisitor {

	protected final PathPredicates predicates;

	public AncestorsRelativeVisitor(PathPredicates predicates) {
		this.predicates = predicates;
	}

	@Override
	public TraceObjectValPath composePath(TraceObjectValPath pre,
			TraceObjectValue value) {
		return pre == null ? TraceObjectValPath.of() : pre.prepend(value);
	}

	@Override
	public VisitResult visitValue(TraceObjectValue value, TraceObjectValPath path) {
		List<String> keyList = path.getKeyList();
		return VisitResult.result(predicates.matches(keyList),
			predicates.ancestorCouldMatchRight(keyList, true) && value.isObject());
	}

	@Override
	public TraceObject continueObject(TraceObjectValue value) {
		return value.getParent();
	}

	@Override
	public Stream<? extends TraceObjectValue> continueValues(TraceObject object,
			Lifespan span, TraceObjectValPath pre) {
		Set<String> prevKeys = predicates.getPrevKeys(pre.getKeyList());
		if (prevKeys.isEmpty()) {
			return Stream.empty();
		}

		return object.getParents()
				.stream()
				.filter(v -> PathPredicates.anyMatches(prevKeys, v.getEntryKey()));
	}
}
