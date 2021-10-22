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
package agent.dbgmodel.dbgmodel.concept;

import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbolEnumerator;
import agent.dbgmodel.dbgmodel.debughost.DebugHostTypeSignature;
import agent.dbgmodel.dbgmodel.main.ModelObject;

/**
 * A wrapper for {@code IDataModelConcept} and its newer variants.
 */
public interface DataModelConcept extends Concept {

	void initializeObject(ModelObject modelObject, DebugHostTypeSignature matchingTypeSignature,
			DebugHostSymbolEnumerator wildcardMatches);

	String getName();
}
