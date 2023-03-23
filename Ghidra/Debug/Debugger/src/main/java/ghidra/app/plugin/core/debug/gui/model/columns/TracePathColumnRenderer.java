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
package ghidra.app.plugin.core.debug.gui.model.columns;

import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class TracePathColumnRenderer<T> extends AbstractGColumnRenderer<T> {
	@Override
	public String getFilterString(T t, Settings settings) {
		return t == null ? "<null>" : t.toString();
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		PathRow row = (PathRow) data.getRowObject();
		if (row.isCurrent()) {
			setBold();
		}
		return this;
	}
}
