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
import java.util.Map;

import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.target.TargetDataTypeMember;

public class TestTargetDataTypeMember
		extends DefaultTestTargetObject<TestTargetObject, TestTargetNamedDataType<?>>
		implements TargetDataTypeMember {

	public TestTargetDataTypeMember(TestTargetTypedefDataType parent, String key, int position,
			long offset,
			String memberName, TargetDataType dataType, String typeHint) {
		super(parent, key, typeHint);

		changeAttributes(List.of(), Map.of(
			POSITION_ATTRIBUTE_NAME, position,
			MEMBER_NAME_ATTRIBUTE_NAME, memberName,
			OFFSET_ATTRIBUTE_NAME, offset,
			DATA_TYPE_ATTRIBUTE_NAME, dataType //
		), "Initialized");
	}
}
