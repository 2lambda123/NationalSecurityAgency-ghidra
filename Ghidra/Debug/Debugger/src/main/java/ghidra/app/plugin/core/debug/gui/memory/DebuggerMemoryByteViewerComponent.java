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
package ghidra.app.plugin.core.debug.gui.memory;

import java.awt.Color;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.plugin.core.byteviewer.*;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.colors.*;
import ghidra.app.plugin.core.debug.gui.colors.MultiSelectionBlendedLayoutBackgroundColorManager.ColoredFieldSelection;
import ghidra.app.plugin.core.format.DataFormatModel;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryState;

public class DebuggerMemoryByteViewerComponent extends ByteViewerComponent
		implements SelectionTranslator {

	protected class SelectionHighlightSelectionGenerator implements SelectionGenerator {
		@Override
		public void addSelections(BigInteger layoutIndex, SelectionTranslator translator,
				List<ColoredFieldSelection> selections) {
			Color selectionColor = paintContext.getSelectionColor();
			Color highlightColor = paintContext.getHighlightColor();
			FieldSelection selection = getSelection();
			if (!selection.isEmpty()) {
				selections.add(new ColoredFieldSelection(selection, selectionColor));
			}
			FieldSelection highlight = getHighlight();
			if (!highlight.isEmpty()) {
				selections.add(new ColoredFieldSelection(highlight, highlightColor));
			}
		}
	}

	protected class TraceMemoryStateSelectionGenerator implements SelectionGenerator {
		@Override
		public void addSelections(BigInteger layoutIndex, SelectionTranslator translator,
				List<ColoredFieldSelection> selections) {
			FieldSelection lineFieldSel = new FieldSelection();
			lineFieldSel.addRange(layoutIndex, layoutIndex.add(BigInteger.ONE));

			DebuggerMemoryBytesProvider provider = panel.getProvider();
			DebuggerCoordinates coordinates = provider.current;
			if (coordinates.getView() == null) {
				return;
			}
			Trace trace = coordinates.getTrace();
			// TODO: Mimic the listing's background, or factor into common
			long viewSnap = coordinates.getViewSnap();
			// TODO: Span out and cache?
			AddressSetView lineAddresses = translator.convertFieldToAddress(lineFieldSel);
			AddressSet known = new AddressSet();
			AddressSet error = new AddressSet();

			for (Address addr : lineAddresses.getAddresses(true)) {
				TraceMemoryState state =
					trace.getMemoryManager().getViewState(viewSnap, addr).getValue();
				switch (state) {
					case KNOWN:
						known.add(addr);
						break;
					case ERROR:
						error.add(addr);
						break;
					default:
						// Don't care
				}
			}
			AddressSet unknown = new AddressSet(lineAddresses);
			unknown.delete(known);
			unknown.delete(error);

			doAddSelections(unknownColor, unknown, translator, selections);
			doAddSelections(errorColor, error, translator, selections);
		}

		protected void doAddSelections(Color color, AddressSetView set,
				SelectionTranslator translator, List<ColoredFieldSelection> selections) {
			if (color == null) {
				return;
			}
			for (AddressRange rng : set) {
				FieldSelection resultFieldSel = translator.convertAddressToField(rng);
				if (resultFieldSel.isEmpty()) {
					continue;
				}
				selections.add(new ColoredFieldSelection(resultFieldSel, color));
			}
		}
	}

	private final DebuggerMemoryBytesPanel panel;

	private Color errorColor = DebuggerResources.COLOR_BACKGROUND_ERROR;
	private Color unknownColor = DebuggerResources.COLOR_BACKGROUND_STALE;

	private final List<SelectionGenerator> selectionGenerators;

	public DebuggerMemoryByteViewerComponent(DebuggerMemoryBytesPanel vpanel,
			ByteViewerLayoutModel layoutModel, DataFormatModel model, int bytesPerLine,
			FontMetrics fm) {
		super(vpanel, layoutModel, model, bytesPerLine, fm);
		// TODO: I don't care much for this reverse path
		this.panel = vpanel;

		selectionGenerators = List.of(
			new SelectionHighlightSelectionGenerator(),
			new TraceMemoryStateSelectionGenerator(),
			vpanel.getProvider().trackingTrait.getSelectionGenerator());
		// NOTE: Cursor, being line-by-line, is done via background color model in super
	}

	@Override
	protected LayoutBackgroundColorManager getLayoutSelectionMap(BigInteger layoutIndex) {
		Color backgroundColor = backgroundColorModel.getBackgroundColor(layoutIndex);
		boolean isBackgroundDefault =
			backgroundColorModel.getDefaultBackgroundColor().equals(backgroundColor);
		List<ColoredFieldSelection> selections = new ArrayList<>(3);
		for (SelectionGenerator sg : selectionGenerators) {
			sg.addSelections(layoutIndex, this, selections);
		}
		return MultiSelectionBlendedLayoutBackgroundColorManager.getLayoutColorMap(
			layoutIndex, selections, backgroundColor, isBackgroundDefault);
	}

	@Override
	public AddressSetView convertFieldToAddress(FieldSelection fieldSelection) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new AddressSet();
		}
		return blockSet.getAddressSet(processFieldSelection(fieldSelection));
	}

	@Override
	public FieldSelection convertAddressToField(AddressSetView addresses) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new FieldSelection();
		}
		return getFieldSelection(blockSet.getBlockSelection(addresses));
	}

	@Override
	public FieldSelection convertAddressToField(AddressRange range) {
		ProgramByteBlockSet blockSet = getBlockSet();
		if (blockSet == null) {
			return new FieldSelection();
		}
		return getFieldSelection(blockSet.getBlockSelection(range));
	}
}
