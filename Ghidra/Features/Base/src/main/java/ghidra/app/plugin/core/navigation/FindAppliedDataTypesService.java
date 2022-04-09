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
package ghidra.app.plugin.core.navigation;

import ghidra.app.services.FieldMatcher;
import ghidra.program.model.data.DataType;

/**
 * A simple service to trigger a search for applied datatypes.
 */
public interface FindAppliedDataTypesService {

	/**
	 * Tells this service to find all places where the given datatype is applied <b>and</b> will
	 * display the results of the search.
	 *
	 * @param dataType The datatype which to base the search upon.
	 */
	public void findAndDisplayAppliedDataTypeAddresses(DataType dataType);

	/**
	 * Tells this service to find all places where the given datatype is applied <b>and</b> will
	 * display the results of the search.
	 *
	 * @param dataType The datatype which to base the search upon.
	 * @param fieldName the sub-field for which to search
	 */
	public void findAndDisplayAppliedDataTypeAddresses(DataType dataType, String fieldName);

	/**
	 * Tells this service to find all places where the given datatype is applied <b>and</b> will
	 * display the results of the search.
	 * <p>
	 * The supplied field matcher will be used to restrict matches to the given field.  The matcher
	 * may be 'empty', supplying only the data type for which to search.  In this case, all uses
	 * of the type will be matched, regardless of field.
	 *
	 * @param dataType The datatype which to base the search upon.
	 * @param fieldMatcher the field matcher.
	 */
	public void findAndDisplayAppliedDataTypeAddresses(DataType dataType,
			FieldMatcher fieldMatcher);
}
