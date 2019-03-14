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
package ghidra.app.plugin.core.datamgr.tree;

import javax.swing.Icon;

import docking.util.MultiIcon;
import ghidra.app.plugin.core.datamgr.archive.BuiltInArchive;

public class BuiltInArchiveNode extends ArchiveNode {

	public BuiltInArchiveNode(BuiltInArchive archive) {
		super(archive);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		Icon baseIcon = archive.getIcon(expanded);
		MultiIcon multiIcon = new MultiIcon(baseIcon);
		return multiIcon;
	}

	@Override
	public String getToolTip() {
		return "Built In Data Types";
	}

}
