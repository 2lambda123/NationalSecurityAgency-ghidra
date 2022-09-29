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

import com.google.common.collect.Range;
import com.google.common.collect.RangeSet;

import docking.widgets.table.*;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.util.table.column.GColumnRenderer;

public class TraceValueLifePlotColumn
		extends AbstractDynamicTableColumn<ValueRow, RangeSet<Long>, Trace> {

	private final RangeSetTableCellRenderer<Long> cellRenderer = new RangeSetTableCellRenderer<>();
	private final RangeCursorTableHeaderRenderer<Long> headerRenderer =
		new RangeCursorTableHeaderRenderer<>();

	@Override
	public String getColumnName() {
		return "Plot";
	}

	@Override
	public RangeSet<Long> getValue(ValueRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject.getLife();
	}

	@Override
	public GColumnRenderer<RangeSet<Long>> getColumnRenderer() {
		return cellRenderer;
	}

	@Override
	public GTableHeaderRenderer getHeaderRenderer() {
		return headerRenderer;
	}

	public void setFullRange(Range<Long> fullRange) {
		cellRenderer.setFullRange(fullRange);
		headerRenderer.setFullRange(fullRange);
	}

	public void setSnap(long snap) {
		headerRenderer.setCursorPosition(snap);
	}

	public void addSeekListener(SeekListener listener) {
		headerRenderer.addSeekListener(listener);
	}
}
