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
package ghidra.app.util.demangler.swift.nodes;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.SwiftDemangledNodeKind;
import ghidra.app.util.demangler.swift.SwiftDemangler;

/**
 * A {@link SwiftDemangledNodeKind#TupleElement} {@link SwiftNode}
 */
public class SwiftTupleElementNode extends SwiftNode {

	@Override
	public Demangled demangle(SwiftDemangler demangler) throws DemangledException {
		Demangled type = null;
		String name = null;
		for (SwiftNode child : getChildren()) {
			switch (child.getKind()) {
				case TupleElementName:
					name = child.getText();
					break;
				case Type:
					type = child.demangle(demangler);
					break;
				default:
					skip(child);
					break;
			}
		}
		if (type == null) {
			return getUnknown();
		}
		if (name != null && type instanceof DemangledDataType ddt) {
			DemangledVariable variable =
				new DemangledVariable(properties.mangled(), properties.originalDemangled(), name);
			variable.setDatatype(ddt);
			return variable;
		}
		return type;
	}

}
