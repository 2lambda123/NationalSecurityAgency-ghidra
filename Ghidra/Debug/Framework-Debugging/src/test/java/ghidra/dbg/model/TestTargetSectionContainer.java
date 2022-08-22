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
package ghidra.dbg.model;

import java.util.List;

import ghidra.dbg.target.TargetSectionContainer;
import ghidra.program.model.address.AddressRange;

public class TestTargetSectionContainer
		extends DefaultTestTargetObject<TestTargetSection, TestTargetModule>
		implements TargetSectionContainer {

	public TestTargetSectionContainer(TestTargetModule parent) {
		super(parent, "Sections", "SectionContainer");
	}

	public TestTargetSection addSection(String name, AddressRange range) {
		TestTargetSection section = getModel().newTestTargetSection(this, name, range);
		changeElements(List.of(), List.of(section), "Add test section: " + name);
		return section;
	}
}
