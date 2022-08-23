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
package ghidra.app.plugin.core.debug.mapping;

import java.util.Objects;

import ghidra.program.model.lang.CompilerSpec;

public abstract class AbstractDebuggerPlatformOffer implements DebuggerPlatformOffer {
	private final String description;
	protected final CompilerSpec cSpec;

	private final int hash;

	public AbstractDebuggerPlatformOffer(String description, CompilerSpec cSpec) {
		this.description = description;
		this.cSpec = cSpec;

		this.hash = Objects.hash(description, cSpec);
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		return cSpec;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		AbstractDebuggerPlatformOffer that = (AbstractDebuggerPlatformOffer) obj;
		if (!Objects.equals(this.description, that.description)) {
			return false;
		}
		if (!Objects.equals(this.cSpec, that.cSpec)) {
			return false;
		}
		return true;
	}
}
