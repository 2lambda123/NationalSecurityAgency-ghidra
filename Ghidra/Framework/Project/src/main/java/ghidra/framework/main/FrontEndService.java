/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.main;

import ghidra.framework.model.ProjectListener;

/**
 * Interface for accessing front-end functionality.
 *
 *
 */
public interface FrontEndService {
	/**
	 * Adds the specified listener to the front-end tool.
	 * @param l the project listener
	 */
	public void addProjectListener(ProjectListener l);

	/**
	 * Removes the specified listener from the front-end tool.
	 * @param l the project listener
	 */
	public void removeProjectListener(ProjectListener l);
}
