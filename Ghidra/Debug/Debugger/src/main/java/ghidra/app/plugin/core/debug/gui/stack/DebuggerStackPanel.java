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
package ghidra.app.plugin.core.debug.gui.stack;

import java.util.List;

import javax.swing.JTable;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectAttributeColumn;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

public class DebuggerStackPanel extends AbstractObjectsTableBasedPanel<TraceObjectStackFrame>
		implements ListSelectionListener {

	private static class FrameLevelColumn extends TraceValueKeyColumn {
		@Override
		public String getColumnName() {
			return "Level";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 48;
		}
	}

	private static class FramePcColumn extends TraceValueObjectAttributeColumn<Address> {
		public FramePcColumn() {
			super(TargetStackFrame.PC_ATTRIBUTE_NAME, Address.class);
		}

		@Override
		public String getColumnName() {
			return "PC";
		}
	}

	private class FrameFunctionColumn
			extends AbstractDynamicTableColumn<ValueRow, Function, Trace> {

		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public Function getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			TraceObjectValue value =
				rowObject.getAttributeEntry(TargetStackFrame.PC_ATTRIBUTE_NAME);
			if (value == null) {
				return null;
			}
			return DebuggerStaticMappingUtils.getFunction(value.castValue(), provider.current,
				serviceProvider);
		}
	}

	private class FrameModuleColumn extends AbstractDynamicTableColumn<ValueRow, String, Trace> {
		@Override
		public String getColumnName() {
			return "Module";
		}

		@Override
		public String getValue(ValueRow rowObject, Settings settings, Trace data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			TraceObjectValue value =
				rowObject.getAttributeEntry(TargetStackFrame.PC_ATTRIBUTE_NAME);
			if (value == null) {
				return null;
			}
			return DebuggerStaticMappingUtils.getModuleName(value.castValue(), provider.current);
		}
	}

	private class StackTableModel extends ObjectTableModel {
		protected StackTableModel(Plugin plugin) {
			super(plugin);
		}

		@Override
		protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
			TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn(new FrameLevelColumn(), 1, true);
			descriptor.addVisibleColumn(new FramePcColumn());
			descriptor.addVisibleColumn(new FrameFunctionColumn());
			descriptor.addVisibleColumn(new FrameModuleColumn());
			return descriptor;
		}
	}

	private final DebuggerStackProvider provider;

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;

	public DebuggerStackPanel(DebuggerStackProvider provider) {
		super(provider.plugin, provider, TraceObjectStackFrame.class);
		this.provider = provider;
	}

	@Override
	protected ObjectTableModel createModel() {
		return new StackTableModel(plugin);
	}

	@Override
	protected ModelQuery computeQuery(TraceObject object) {
		TargetObjectSchema rootSchema = object.getRoot().getTargetSchema();
		List<String> stackPath = rootSchema
				.searchForSuitable(TargetStack.class, object.getCanonicalPath().getKeyList());
		if (stackPath == null) {
			return ModelQuery.EMPTY;
		}
		TargetObjectSchema stackSchema = rootSchema.getSuccessorSchema(stackPath);
		PathMatcher matcher = stackSchema.searchFor(TargetStackFrame.class, stackPath, true);
		return new ModelQuery(matcher);
	}

	@Override
	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		super.coordinatesActivated(coordinates);
		TraceObject object = coordinates.getObject();
		if (object != null) {
			trySelectAncestor(object);
		}
	}

	@Override
	public void cellActivated(JTable table) {
		/**
		 * Override, because PC columns is fairly wide and representative of the stack frame.
		 * Likely, when the user double-clicks, they mean to activate the frame, even if it happens
		 * to be in that column. Simply going to the address will confuse and/or disappoint.
		 */
		ValueRow item = getSelectedItem();
		if (item != null) {
			traceManager.activateObject(item.getValue().getChild());
		}
	}
}
