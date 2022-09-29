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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.awt.Color;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.app.util.viewer.listingpanel.MarkerClickedListener;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;

@PluginInfo(
	shortDescription = "Debugger breakpoint marker service plugin",
	description = "Marks logical breakpoints and provides actions in the listings",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerLogicalBreakpointService.class,
		MarkerService.class,
	})
public class DebuggerBreakpointMarkerPlugin extends Plugin
		implements PopupActionProvider {

	protected static Address computeAddressFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return range.getMinAddress();
				}
			}
			return ctx.getAddress();
		}
		Object obj = context.getContextObject();
		if (obj instanceof MarkerLocation) {
			MarkerLocation ml = (MarkerLocation) obj;
			return ml.getAddr();
		}
		return null;
	}

	/**
	 * Attempt to derive a location from the given context
	 * 
	 * <p>
	 * Currently, this supports {@link ProgramLocationActionContext} and {@link MarkerLocation}.
	 * 
	 * @param context a possible location context
	 * @return the program location, or {@code null}
	 */
	protected static ProgramLocation getLocationFromContext(ActionContext context) {
		if (context == null) {
			return null;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return new ProgramLocation(ctx.getProgram(), range.getMinAddress());
				}
			}
			return ctx.getLocation();
		}
		Object obj = context.getContextObject();
		if (obj instanceof MarkerLocation) {
			MarkerLocation ml = (MarkerLocation) obj;
			return new ProgramLocation(ml.getProgram(), ml.getAddr());
		}
		return null;
	}

	protected static long computeLengthFromContext(ActionContext context) {
		if (context == null) {
			return 1;
		}
		if (context instanceof ProgramLocationActionContext) {
			ProgramLocationActionContext ctx = (ProgramLocationActionContext) context;
			if (ctx.hasSelection()) {
				ProgramSelection sel = ctx.getSelection();
				AddressRange range = sel.getRangeContaining(ctx.getAddress());
				if (range != null) {
					return range.getLength();
				}
			}
			CodeUnit cu = ctx.getCodeUnit();
			if (cu instanceof Data) {
				return cu.getLength();
			}
		}
		return 1;
	}

	protected static boolean contextHasLocation(ActionContext context) {
		return getLocationFromContext(context) != null;
	}

	protected static Trace getTraceFromContext(ActionContext context) {
		ProgramLocation loc = getLocationFromContext(context);
		if (loc == null) {
			return null;
		}
		Program progOrView = loc.getProgram();
		if (progOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) progOrView;
			return view.getTrace();
		}
		return null;
	}

	protected static boolean contextHasTrace(ActionContext context) {
		return getTraceFromContext(context) != null;
	}

	protected static long computeDefaultLength(ActionContext context,
			Collection<TraceBreakpointKind> selected) {
		if (selected.isEmpty() ||
			selected.contains(TraceBreakpointKind.HW_EXECUTE) ||
			selected.contains(TraceBreakpointKind.SW_EXECUTE)) {
			return 1;
		}
		return computeLengthFromContext(context);
	}

	protected static Set<TraceBreakpointKind> computeDefaultKinds(ActionContext ctx,
			Collection<TraceBreakpointKind> supported) {
		if (supported.isEmpty()) {
			return Set.of();
		}
		long length = computeLengthFromContext(ctx);
		if (length == 1) {
			ProgramLocation loc = getLocationFromContext(ctx);
			Listing listing = loc.getProgram().getListing();
			CodeUnit cu = listing.getCodeUnitContaining(loc.getAddress());
			if (cu instanceof Instruction) {
				if (supported.contains(TraceBreakpointKind.SW_EXECUTE)) {
					return Set.of(TraceBreakpointKind.SW_EXECUTE);
				}
				else if (supported.contains(TraceBreakpointKind.HW_EXECUTE)) {
					return Set.of(TraceBreakpointKind.HW_EXECUTE);
				}
				return Set.of();
			}
			Data data = (Data) cu;
			if (!data.isDefined()) {
				if (supported.size() == 1) {
					return Set.copyOf(supported);
				}
				return Set.of();
			}
		}
		// TODO: Consider memory protections?
		Set<TraceBreakpointKind> result =
			new HashSet<>(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
		result.retainAll(supported);
		return result;
	}

	protected Color colorForState(State state) {
		if (state.isEnabled()) {
			if (state.isEffective()) {
				return breakpointEnabledMarkerColor;
			}
			else {
				return breakpointIneffEnMarkerColor;
			}
		}
		else {
			if (state.isEffective()) {
				return breakpointDisabledMarkerColor;
			}
			else {
				return breakpointIneffDisMarkerColor;
			}
		}
	}

	protected boolean stateColorsBackground(State state) {
		if (state.isEnabled()) {
			if (state.isEffective()) {
				return breakpointEnabledColoringBackground;
			}
			else {
				return breakpointIneffEnColoringBackground;
			}
		}
		else {
			if (state.isEffective()) {
				return breakpointDisabledColoringBackground;
			}
			else {
				return breakpointIneffDisColoringBackground;
			}
		}
	}

	/**
	 * A variety of marker sets (one for each logical state) attached to a program or trace view
	 */
	protected class BreakpointMarkerSets {
		final Program program;

		final Map<State, MarkerSet> sets = new HashMap<>();

		protected BreakpointMarkerSets(Program program) {
			this.program = program;

			// Prevent default bookmark icons from obscuring breakpoints
			if (!(program instanceof TraceProgramView)) {
				BookmarkManager manager = program.getBookmarkManager();
				manager.defineType(LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					MarkerService.BREAKPOINT_PRIORITY - 1);
				manager.defineType(LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE,
					DebuggerResources.ICON_BLANK,
					DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS,
					MarkerService.BREAKPOINT_PRIORITY - 1);
			}

			for (State state : State.values()) {
				getMarkerSet(state);
			}
		}

		MarkerSet getMarkerSet(State state) {
			return sets.computeIfAbsent(state, this::doGetMarkerSet);
		}

		MarkerSet doGetMarkerSet(State state) {
			if (state.icon == null) {
				return null;
			}
			MarkerSet set = markerService.getMarkerSet(state.display, program);
			if (set != null) {
				return set;
			}
			return markerService.createPointMarker(state.display, state.display, program,
				MarkerService.BREAKPOINT_PRIORITY, true, true, stateColorsBackground(state),
				colorForState(state), state.icon, true);
		}

		public void setEnabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setDisabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setIneffectiveEnabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setIneffectiveDisabledMarkerColor(Color color) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setMarkerColor(color);
			}
		}

		public void setEnabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setDisabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || !state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveEnabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || !state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void setIneffectiveDisabledColoringBackground(boolean coloringBackground) {
			for (State state : State.values()) {
				if (state == State.NONE || state.isEnabled() || state.isEffective()) {
					continue;
				}
				getMarkerSet(state).setColoringBackground(coloringBackground);
			}
		}

		public void dispose() {
			for (State state : State.values()) {
				MarkerSet set = sets.get(state);
				if (set != null) {
					markerService.removeMarker(set, program);
				}
			}
		}

		public void clear() {
			for (State state : State.values()) {
				MarkerSet set = sets.get(state);
				if (set != null) {
					set.clearAll();
				}
			}
		}
	}

	private class UpdateMarksBreakpointRecordChangeListener
			implements LogicalBreakpointsChangeListener {
		@Override
		public void breakpointAdded(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}

		@Override
		public void breakpointUpdated(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}

		@Override
		public void breakpointRemoved(LogicalBreakpoint breakpoint) {
			updateDebouncer.contact(null);
		}
	}

	private class ToggleBreakpointsMarkerClickedListener implements MarkerClickedListener {
		@Override
		public void markerDoubleClicked(MarkerLocation location) {
			ProgramLocationActionContext context =
				new ProgramLocationActionContext(null, location.getProgram(),
					new ProgramLocation(location.getProgram(), location.getAddr()), null, null);
			if (contextCanManipulateBreakpoints(context)) {
				doToggleBreakpointsAt(ToggleBreakpointAction.NAME, context);
			}
		}
	}

	protected static State computeState(LogicalBreakpoint breakpoint, Program programOrView) {
		if (programOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) programOrView;
			return breakpoint.computeStateForTrace(view.getTrace());
		}
		// Program view should consider all trace placements
		// TODO: A mode for only considering the current trace (for effectiveness in program)
		return breakpoint.computeState();
	}

	/**
	 * It seems the purpose of this was to omit the program mode from the dynamic listing. I don't
	 * think we need that anymore, so I've just delegated to exactly the same as the breakpoint
	 * service, which will include the program mode, if applicable. TODO: Remove this and just call
	 * the service's version directly?
	 * 
	 * @param loc
	 * @return
	 */
	protected State computeState(ProgramLocation loc) {
		return breakpointService.computeState(loc);
	}

	protected class ToggleBreakpointAction extends AbstractToggleBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public ToggleBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setKeyBindingData(new KeyBindingData(KeyEvent.VK_K, 0));
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			doToggleBreakpointsAt(NAME, context);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			return true;
		}
	}

	protected class SetBreakpointAction extends AbstractSetBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		private final Set<TraceBreakpointKind> kinds;

		public SetBreakpointAction(Set<TraceBreakpointKind> kinds) {
			super(DebuggerBreakpointMarkerPlugin.this);
			this.kinds = kinds;
			setPopupMenuData(new MenuData(
				new String[] { NAME, TraceBreakpointKindSet.encode(kinds) }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			ProgramLocation location = getLocationFromContext(context);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, NAME, location, length, kinds,
				"");
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation loc = getLocationFromContext(context);
			if (!(loc.getProgram() instanceof TraceProgramView)) {
				return true;
			}
			TraceRecorder recorder = getRecorderFromContext(context);
			if (recorder == null) {
				return false;
			}
			if (!recorder.getSupportedBreakpointKinds().containsAll(kinds)) {
				return false;
			}
			return true;
		}
	}

	protected class EnableBreakpointAction extends AbstractEnableBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public EnableBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
			Trace trace = getTraceFromContext(context);
			String status = breakpointService.generateStatusEnable(col, trace);
			if (status != null) {
				tool.setStatusInfo(status, true);
			}
			breakpointService.enableAll(col, trace).exceptionally(ex -> {
				breakpointError(NAME, "Could not enable breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation location = getLocationFromContext(context);
			State state = computeState(location);
			if (state == State.ENABLED || state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	protected class DisableBreakpointAction extends AbstractDisableBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public DisableBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
			breakpointService.disableAll(col, getTraceFromContext(context)).exceptionally(ex -> {
				breakpointError(NAME, "Could not disable breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation location = getLocationFromContext(context);
			State state = computeState(location);
			if (state == State.DISABLED || state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	// TODO: Make sub-menu listing all breakpoints present here?
	// TODO:     If so, include a "remove all" (at this address) action
	protected class ClearBreakpointAction extends AbstractClearBreakpointAction {
		public static final String GROUP = DebuggerResources.GROUP_BREAKPOINTS;

		public ClearBreakpointAction() {
			super(DebuggerBreakpointMarkerPlugin.this);
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return;
			}
			ProgramLocation location = getLocationFromContext(context);
			Set<LogicalBreakpoint> col = breakpointService.getBreakpointsAt(location);
			breakpointService.deleteAll(col, getTraceFromContext(context)).exceptionally(ex -> {
				breakpointError(NAME, "Could not delete breakpoint", ex);
				return null;
			});
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!contextCanManipulateBreakpoints(context)) {
				return false;
			}
			ProgramLocation location = getLocationFromContext(context);
			State state = computeState(location);
			if (state == State.NONE) {
				return false;
			}
			return true;
		}
	}

	// @AutoServiceConsumed via method
	private MarkerService markerService;
	// @AutoServiceConsumed via method
	private DebuggerLogicalBreakpointService breakpointService;
	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an enabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointEnabledMarkerColor =
		DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an enabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointEnabledColoringBackground =
		DebuggerResources.DEFAULT_COLOR_ENABLED_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_MARKERS, //
		description = "Background color for memory at a disabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointDisabledMarkerColor =
		DebuggerResources.DEFAULT_COLOR_DISABLED_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at a disabled breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointDisabledColoringBackground =
		DebuggerResources.DEFAULT_COLOR_DISABLED_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffEnMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFF_EN_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an enabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffEnColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_MARKERS, //
		description = "Background color for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private Color breakpointIneffDisMarkerColor =
		DebuggerResources.DEFAULT_COLOR_INEFF_DIS_BREAKPOINT_MARKERS;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND, //
		description = "Whether or not to color background for memory at an disabled, but ineffective, breakpoint", //
		help = @HelpInfo(anchor = "colors"))
	private boolean breakpointIneffDisColoringBackground =
		DebuggerResources.DEFAULT_COLOR_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final Map<Program, BreakpointMarkerSets> markersByProgram = new HashMap<>();

	private final LogicalBreakpointsChangeListener updateMarksListener =
		new UpdateMarksBreakpointRecordChangeListener();
	private final MarkerClickedListener markerClickedListener =
		new ToggleBreakpointsMarkerClickedListener();

	private final AsyncDebouncer<Void> updateDebouncer =
		new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 50);

	// package access for testing
	SetBreakpointAction actionSetSoftwareBreakpoint;
	SetBreakpointAction actionSetExecuteBreakpoint;
	SetBreakpointAction actionSetReadWriteBreakpoint;
	SetBreakpointAction actionSetReadBreakpoint;
	SetBreakpointAction actionSetWriteBreakpoint;
	ToggleBreakpointAction actionToggleBreakpoint;
	EnableBreakpointAction actionEnableBreakpoint;
	DisableBreakpointAction actionDisableBreakpoint;
	ClearBreakpointAction actionClearBreakpoint;

	DebuggerPlaceBreakpointDialog placeBreakpointDialog = new DebuggerPlaceBreakpointDialog();

	public DebuggerBreakpointMarkerPlugin(PluginTool tool) {
		super(tool);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
		this.autoOptionsWiring = AutoOptions.wireOptions(this);

		updateDebouncer.addListener(__ -> SwingUtilities.invokeLater(() -> updateAllMarks()));

		tool.addPopupActionProvider(this);
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_MARKERS)
	private void setEnabledBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setEnabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND)
	private void setEnabledBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setEnabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_MARKERS)
	private void setDisabledBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setDisabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND)
	private void setDisabledBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setDisabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_MARKERS)
	private void setIneffectiveEBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_EN_BREAKPOINT_COLORING_BACKGROUND)
	private void setIneffectiveEBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveEnabledColoringBackground(breakpointColoringBackground);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_MARKERS)
	private void setIneffectiveDBreakpointMarkerColor(Color breakpointMarkerColor) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveDisabledMarkerColor(breakpointMarkerColor);
		}
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_INEFF_DIS_BREAKPOINT_COLORING_BACKGROUND)
	private void setIneffectiveDBreakpointMarkerBackground(boolean breakpointColoringBackground) {
		for (BreakpointMarkerSets markers : markersByProgram.values()) {
			markers.setIneffectiveDisabledColoringBackground(breakpointColoringBackground);
		}
	}

	protected TraceRecorder getRecorderFromContext(ActionContext context) {
		if (modelService == null) {
			return null;
		}
		Trace trace = getTraceFromContext(context);
		return modelService.getRecorder(trace);
	}

	protected Set<TraceRecorder> getRecordersFromContext(ActionContext context) {
		TraceRecorder single = getRecorderFromContext(context);
		if (single != null) {
			return Set.of(single);
		}
		if (mappingService == null || modelService == null) {
			return Set.of();
		}
		ProgramLocation loc = getLocationFromContext(context);
		if (loc == null || loc.getProgram() instanceof TraceProgramView) {
			return Set.of();
		}
		Set<TraceRecorder> result = new HashSet<>();
		for (TraceLocation tloc : mappingService.getOpenMappedLocations(loc)) {
			TraceRecorder rec = modelService.getRecorder(tloc.getTrace());
			if (rec != null) {
				result.add(rec);
			}
		}
		return result;
	}

	protected boolean contextHasRecorder(ActionContext ctx) {
		return getRecorderFromContext(ctx) != null;
	}

	protected boolean contextCanManipulateBreakpoints(ActionContext ctx) {
		if (breakpointService == null) {
			return false;
		}
		if (!contextHasLocation(ctx)) {
			return false;
		}
		// Programs, or live traces, but not dead traces
		if (contextHasTrace(ctx) && !contextHasRecorder(ctx)) {
			return false;
		}
		return true;
	}

	protected Set<TraceBreakpointKind> getSupportedKindsFromContext(ActionContext context) {
		Set<TraceRecorder> recorders = getRecordersFromContext(context);
		if (recorders.isEmpty()) {
			return EnumSet.allOf(TraceBreakpointKind.class);
		}
		return recorders.stream()
				.flatMap(rec -> rec.getSupportedBreakpointKinds().stream())
				.collect(Collectors.toSet());
	}

	protected void doToggleBreakpointsAt(String title, ActionContext context) {
		if (breakpointService == null) {
			return;
		}
		ProgramLocation loc = getLocationFromContext(context);
		if (loc == null) {
			return;
		}
		String status = breakpointService.generateStatusToggleAt(loc);
		if (status != null) {
			tool.setStatusInfo(status, true);
		}
		breakpointService.toggleBreakpointsAt(loc, () -> {
			Set<TraceBreakpointKind> supported = getSupportedKindsFromContext(context);
			if (supported.isEmpty()) {
				breakpointError(title, "It seems this target does not support breakpoints.");
				return CompletableFuture.completedFuture(Set.of());
			}
			Set<TraceBreakpointKind> kinds = computeDefaultKinds(context, supported);
			long length = computeDefaultLength(context, kinds);
			placeBreakpointDialog.prompt(tool, breakpointService, title, loc, length, kinds, "");
			// Not great, but I'm not sticking around for the dialog
			return CompletableFuture.completedFuture(Set.of());
		}).exceptionally(ex -> {
			breakpointError(title, "Could not toggle breakpoints", ex);
			return null;
		});
	}

	/**
	 * Instantiate a marker set for the given program or trace view
	 * 
	 * @param program the (static) program or (dynamic) trace view
	 * @return the marker sets
	 */
	protected BreakpointMarkerSets createMarkers(Program program) {
		synchronized (markersByProgram) {
			BreakpointMarkerSets newSets = new BreakpointMarkerSets(program);
			BreakpointMarkerSets oldSets = markersByProgram.put(program, newSets);
			assert oldSets == null;
			return newSets;
		}
	}

	protected void removeMarkers(Program program) {
		synchronized (markersByProgram) {
			BreakpointMarkerSets oldSets = markersByProgram.remove(program);
			oldSets.dispose();
		}
	}

	protected void doMarks(BreakpointMarkerSets marks,
			Map<Address, Set<LogicalBreakpoint>> byAddress,
			java.util.function.Function<LogicalBreakpoint, State> stateFunc) {
		for (Map.Entry<Address, Set<LogicalBreakpoint>> bEnt : byAddress.entrySet()) {
			Map<Long, State> byLength = new HashMap<>();
			for (LogicalBreakpoint lb : bEnt.getValue()) {
				byLength.compute(lb.getLength(), (l, e) -> (e == null ? State.NONE : e)
						.sameAdddress(stateFunc.apply(lb)));
			}
			Address start = bEnt.getKey();
			for (Map.Entry<Long, State> sEnt : byLength.entrySet()) {
				Address end = start.add(sEnt.getKey() - 1);
				MarkerSet set = marks.getMarkerSet(sEnt.getValue());
				if (set != null) {
					set.add(start, end);
				}
			}
		}
	}

	protected void updateAllMarks() {
		synchronized (markersByProgram) {
			for (BreakpointMarkerSets markerSet : markersByProgram.values()) {
				markerSet.clear();
			}
			if (breakpointService == null) {
				return;
			}
			for (Map.Entry<Program, BreakpointMarkerSets> pEnt : markersByProgram.entrySet()) {
				Program program = pEnt.getKey();
				BreakpointMarkerSets marks = pEnt.getValue();
				if (program instanceof TraceProgramView) {
					TraceProgramView view = (TraceProgramView) program;
					Trace trace = view.getTrace();
					doMarks(marks, breakpointService.getBreakpoints(trace),
						lb -> lb.computeStateForTrace(trace));
				}
				else {
					doMarks(marks, breakpointService.getBreakpoints(program),
						lb -> lb.computeStateForProgram(program));
				}
			}
		}
	}

	@AutoServiceConsumed
	private void setMarkerService(MarkerService markerService) {
		if (this.markerService != null) {
			this.markerService.setMarkerClickedListener(null);
		}
		this.markerService = markerService;
		if (this.markerService != null) {
			this.markerService.setMarkerClickedListener(markerClickedListener);
		}
	}

	@AutoServiceConsumed
	private void setLogicalBreakpointService(DebuggerLogicalBreakpointService breakpointService) {
		if (this.breakpointService != null) {
			this.breakpointService.removeChangeListener(updateMarksListener);
		}
		this.breakpointService = breakpointService;
		if (this.breakpointService != null) {
			breakpointService.addChangeListener(updateMarksListener);
			updateAllMarks();
		}
	}

	protected void createActions() {
		actionSetSoftwareBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.SW_EXECUTE));
		actionSetExecuteBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.HW_EXECUTE));
		actionSetReadWriteBreakpoint =
			new SetBreakpointAction(Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE));
		actionSetReadBreakpoint = new SetBreakpointAction(Set.of(TraceBreakpointKind.READ));
		actionSetWriteBreakpoint = new SetBreakpointAction(Set.of(TraceBreakpointKind.WRITE));
		actionToggleBreakpoint = new ToggleBreakpointAction();
		actionEnableBreakpoint = new EnableBreakpointAction();
		actionDisableBreakpoint = new DisableBreakpointAction();
		actionClearBreakpoint = new ClearBreakpointAction();

		tool.setMenuGroup(new String[] { SetBreakpointAction.NAME }, SetBreakpointAction.GROUP);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool __, ActionContext context) {
		return List.of(); // TODO: Actions by individual breakpoint?
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent evt = (ProgramOpenedPluginEvent) event;
			createMarkers(evt.getProgram());
			updateAllMarks();
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent evt = (ProgramClosedPluginEvent) event;
			removeMarkers(evt.getProgram());
		}
		else if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent evt = (TraceOpenedPluginEvent) event;
			TraceProgramView view = evt.getTrace().getProgramView();
			createMarkers(view);
			updateAllMarks();
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent evt = (TraceClosedPluginEvent) event;
			Trace trace = evt.getTrace();
			Map<Program, BreakpointMarkerSets> copyOfMarkers;
			synchronized (markersByProgram) {
				copyOfMarkers = Map.copyOf(markersByProgram);
			}
			for (Map.Entry<Program, BreakpointMarkerSets> ent : copyOfMarkers.entrySet()) {
				Program program = ent.getKey();
				if (!(program instanceof TraceProgramView)) {
					continue;
				}
				TraceProgramView view = (TraceProgramView) program;
				if (view.getTrace() != trace) {
					continue;
				}
				removeMarkers(view);
			}
		}
	}

	protected void breakpointError(String title, String message) {
		if (consoleService == null) {
			Msg.showError(this, null, title, message);
			return;
		}
		consoleService.log(DebuggerResources.ICON_LOG_ERROR, message);
	}

	protected void breakpointError(String title, String message, Throwable ex) {
		if (consoleService == null) {
			Msg.showError(this, null, title, message, ex);
			return;
		}
		Msg.error(this, message, ex);
		consoleService.log(DebuggerResources.ICON_LOG_ERROR, message + " (" + ex + ")");
	}
}
