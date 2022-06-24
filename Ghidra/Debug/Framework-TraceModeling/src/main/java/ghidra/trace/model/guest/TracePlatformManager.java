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
package ghidra.trace.model.guest;

import java.util.Collection;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;

/**
 * Allows the addition of "guest platforms" for disassembling in multiple languages.
 * 
 * <p>
 * TODO: Allow the placement of data units with alternative data organization.
 */
public interface TracePlatformManager {
	/**
	 * Get the base language of the trace
	 * 
	 * @return the language
	 */
	Language getBaseLanguage();

	/**
	 * Get the base compiler spec of the trace
	 * 
	 * @return the compiler spec
	 */
	CompilerSpec getBaseCompilerSpec();

	/**
	 * Add a guest platform
	 * 
	 * @param compilerSpec the compiler spec, which cannot be the base compiler spec
	 * @return the new platform
	 */
	TraceGuestPlatform addGuestPlatform(CompilerSpec compilerSpec);

	/**
	 * Get the guest platform for the given compiler spec
	 * 
	 * @param compilerSpec the compiler spec. For the base compiler spec, this will return null.
	 * @return the platform, if found, or null
	 */
	TraceGuestPlatform getGuestPlatform(CompilerSpec compilerSpec);

	/**
	 * Get or add a platform for the given compiler spec
	 * 
	 * @param compilerSpec the compiler spec
	 * @return the new or existing platform, or null if compiler spec is the base compiler spec
	 */
	TraceGuestPlatform getOrAddGuestPlatform(CompilerSpec compilerSpec);

	/**
	 * Get all guest platforms
	 * 
	 * @return the collection of platforms
	 */
	Collection<TraceGuestPlatform> getGuestPlatforms();
}
