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
package generic.theme.builtin;

import javax.swing.LookAndFeel;

import generic.theme.DiscoverableGTheme;
import generic.theme.LafType;

/**
 * Built-in GTheme that uses the Nimbus {@link LookAndFeel} and the standard (light)
 * application defaults.
 */
public class NimbusTheme extends DiscoverableGTheme {

	public NimbusTheme() {
		super("Nimbus Theme", LafType.NIMBUS);
	}

}
