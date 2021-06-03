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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetDeletable;

public class DeleteBreakpointActionItem implements BreakpointActionItem {
	private final TargetBreakpointSpec spec;

	public DeleteBreakpointActionItem(TargetBreakpointSpec spec) {
		this.spec = spec;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DeleteBreakpointActionItem)) {
			return false;
		}
		DeleteBreakpointActionItem that = (DeleteBreakpointActionItem) obj;
		if (this.spec != that.spec) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getClass(), spec);
	}

	@Override
	public CompletableFuture<Void> execute() {
		if (!(spec instanceof TargetDeletable)) {
			return CompletableFuture
					.failedFuture(new IllegalArgumentException("spec is not Deletable"));
		}
		TargetDeletable del = (TargetDeletable) spec;
		return del.delete();
	}
}
