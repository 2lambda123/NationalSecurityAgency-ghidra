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
package ghidra.app.plugin.core.debug.gui.modules;

import java.awt.event.MouseEvent;
import java.io.File;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.ArrayUtils;

import docking.*;
import docking.action.*;
import docking.action.builder.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.action.AutoMapSpec;
import ghidra.app.plugin.core.debug.gui.action.AutoMapSpec.AutoMapSpecConfigFieldCodec;
import ghidra.app.plugin.core.debug.gui.action.ByModuleAutoMapSpec;
import ghidra.app.plugin.core.debug.service.model.TraceRecorderTarget;
import ghidra.app.plugin.core.debug.service.modules.MapModulesBackgroundCommand;
import ghidra.app.plugin.core.debug.service.modules.MapSectionsBackgroundCommand;
import ghidra.app.services.*;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.modules.*;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.util.TraceEvent;
import ghidra.trace.util.TraceEvents;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class DebuggerModulesProvider extends ComponentProviderAdapter {
	protected static final AutoConfigState.ClassHandler<DebuggerModulesProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerModulesProvider.class, MethodHandles.lookup());

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (a.getSnap() != b.getSnap()) {
			return false;
		}
		if (!Objects.equals(a.getObject(), b.getObject())) {
			return false;
		}
		return true;
	}

	interface MapIdenticallyAction {
		String NAME = DebuggerResources.NAME_MAP_IDENTICALLY;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_IDENTICALLY;
		Icon ICON = DebuggerResources.ICON_MAP_IDENTICALLY;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_identically";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapManuallyAction {
		String NAME = DebuggerResources.NAME_MAP_MANUALLY;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MANUALLY;
		Icon ICON = DebuggerResources.ICON_MAP_MANUALLY;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_manually";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModulesAction {
		String NAME = "Map Modules";
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MODULES;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_modules";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModuleToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_MODULE_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MODULE_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_module_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsAction {
		String NAME = DebuggerResources.NAME_MAP_SECTIONS;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTIONS;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_SECTION_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTION_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_section_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_SECTIONS_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTIONS_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface AutoMapAction {
		String NAME = "Auto-Map Target Memory";
		Icon ICON = DebuggerResources.ICON_MAP_AUTO;
		String DESCRIPTION = "Automatically map dynamic memory to static counterparts";
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "auto_map";

		static MultiStateActionBuilder<AutoMapSpec> builder(Plugin owner) {
			String ownerName = owner.getName();
			MultiStateActionBuilder<AutoMapSpec> builder =
				new MultiStateActionBuilder<AutoMapSpec>(NAME, ownerName)
						.description(DESCRIPTION)
						.toolBarGroup(GROUP)
						.toolBarIcon(ICON)
						.useCheckboxForIcons(true)
						.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
			for (AutoMapSpec spec : AutoMapSpec.allSpecs().values()) {
				builder.addState(spec.getMenuName(), spec.getMenuIcon(), spec);
			}
			return builder;
		}
	}

	interface ImportMissingModuleAction {
		String NAME = "Import Missing Module";
		String DESCRIPTION = "Import the missing module from disk";
		Icon ICON = DebuggerResources.ICON_IMPORT;
		String HELP_ANCHOR = "import_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingModuleAction {
		String NAME = "Map Missing Module";
		String DESCRIPTION = "Map the missing module to an existing import";
		Icon ICON = DebuggerResources.ICON_MAP_MODULES;
		String HELP_ANCHOR = "map_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ShowSectionsTableAction {
		String NAME = "Show Sections Table";
		Icon ICON = new GIcon("icon.debugger.modules.table.sections");
		String DESCRIPTION = "Toggle display fo the Sections Table pane";
		String GROUP = DebuggerResources.FilterAction.GROUP;
		String ORDER = "1";
		String HELP_ANCHOR = "show_sections_table";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, ORDER)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected class ForMappingTraceListener extends TraceDomainObjectListener {
		public ForMappingTraceListener(AutoMapSpec spec) {
			for (TraceEvent<?, ?> type : spec.getChangeTypes()) {
				listenFor(type, this::changed);
			}

			// Delete this if/when TraceRecorderTarget is removed
			listenFor(TraceEvents.BYTES_CHANGED, this::memoryChanged);
		}

		private void changed() {
			cueAutoMap = true;
		}

		private void memoryChanged(TraceAddressSnapRange range) {
			if (range.getRange().getAddressSpace().isRegisterSpace()) {
				return;
			}
			if (current.getTarget() instanceof TraceRecorderTarget) {
				doCuedAutoMap();
			}
		}
	}

	protected static Set<TraceModule> getSelectedModules(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return DebuggerLegacyModulesPanel.getSelectedModulesFromContext(ctx);
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return DebuggerLegacySectionsPanel.getSelectedModulesFromContext(ctx);
		}
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedModulesFromContext(ctx);
		}
		return Set.of();
	}

	protected static Set<TraceSection> getSelectedSections(ActionContext context,
			boolean allowExpansion) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return DebuggerLegacyModulesPanel.getSelectedSectionsFromContext(ctx);
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return DebuggerLegacySectionsPanel.getSelectedSectionsFromContext(ctx, allowExpansion);
		}
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedSectionsFromContext(ctx);
		}
		return Set.of();
	}

	protected static AddressSetView getSelectedAddresses(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return DebuggerLegacyModulesPanel.getSelectedAddressesFromContext(ctx);
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return DebuggerLegacySectionsPanel.getSelectedAddressesFromContext(ctx);
		}
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedAddressesFromContext(ctx);
		}
		return null;
	}

	protected class SelectAddressesAction extends AbstractSelectAddressesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public SelectAddressesAction() {
			super(plugin);
			setDescription("Select addresses contained in modules or sections");
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (listingService == null) {
				return;
			}

			AddressSetView sel = getSelectedAddresses(context);
			if (sel == null || sel.isEmpty()) {
				return;
			}

			sel = sel.intersect(traceManager.getCurrentView().getMemory());
			ProgramSelection ps = new ProgramSelection(sel);
			listingService.setCurrentSelection(ps);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isContextNonEmpty(context);
		}
	}

	protected class ImportFromFileSystemAction extends AbstractImportFromFileSystemAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public ImportFromFileSystemAction() {
			super(plugin);
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (importerService == null) {
				return;
			}
			Set<TraceModule> modules = getSelectedModules(context);
			if (modules == null || modules.size() != 1) {
				return;
			}
			TraceModule mod = modules.iterator().next();
			importModuleFromFileSystem(mod);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			try {
				Set<TraceModule> sel = getSelectedModules(context);
				return importerService != null && sel != null && sel.size() == 1;
			}
			catch (TraceClosedException e) {
				return false;
			}
		}
	}

	final DebuggerModulesPlugin plugin;

	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	ProgramManager programManager;
	@AutoServiceConsumed
	private GoToService goToService;
	@AutoServiceConsumed
	private FileImporterService importerService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final JSplitPane mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
	private final int defaultDividerSize = mainPanel.getDividerSize();

	DebuggerModulesPanel modulesPanel;
	DebuggerLegacyModulesPanel legacyModulesPanel;
	DebuggerSectionsPanel sectionsPanel;
	DebuggerLegacySectionsPanel legacySectionsPanel;

	// TODO: Lazy construction of these dialogs?
	private final DebuggerBlockChooserDialog blockChooserDialog;
	private final DebuggerModuleMapProposalDialog moduleProposalDialog;
	private final DebuggerSectionMapProposalDialog sectionProposalDialog;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	private ActionContext myActionContext;

	DockingAction actionMapIdentically;
	DockingAction actionMapManually;
	DockingAction actionMapModules;
	DockingAction actionMapModuleTo;
	DockingAction actionMapSections;
	DockingAction actionMapSectionTo;
	DockingAction actionMapSectionsTo;

	MultiStateDockingAction<AutoMapSpec> actionAutoMap;
	private final AutoMapSpec defaultAutoMapSpec =
		AutoMapSpec.fromConfigName(ByModuleAutoMapSpec.CONFIG_NAME);

	@AutoConfigStateField(codec = AutoMapSpecConfigFieldCodec.class)
	AutoMapSpec autoMapSpec = defaultAutoMapSpec;
	@AutoConfigStateField
	boolean showSectionsTable = true;
	@AutoConfigStateField
	boolean filterSectionsByModules = false;

	boolean cueAutoMap;
	private ForMappingTraceListener forMappingListener;

	DockingAction actionImportMissingModule;
	DockingAction actionMapMissingModule;

	SelectAddressesAction actionSelectAddresses;
	ImportFromFileSystemAction actionImportFromFileSystem;
	ToggleDockingAction actionShowSectionsTable;
	ToggleDockingAction actionFilterSectionsByModules;
	DockingAction actionSelectCurrent;

	public DebuggerModulesProvider(final DebuggerModulesPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_MODULES, plugin.getName(), null);
		this.plugin = plugin;

		setIcon(DebuggerResources.ICON_PROVIDER_MODULES);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_MODULES);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		blockChooserDialog = new DebuggerBlockChooserDialog(tool);
		moduleProposalDialog = new DebuggerModuleMapProposalDialog(this);
		sectionProposalDialog = new DebuggerSectionMapProposalDialog(this);

		setDefaultWindowPosition(WindowPosition.LEFT);
		setVisible(true);
		createActions();
	}

	private void importModuleFromFileSystem(TraceModule module) {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setSelectedFile(new File(module.getName()));
		File file = chooser.getSelectedFile();
		chooser.dispose();
		if (file == null) { // Perhaps cancelled
			return;
		}
		Project activeProject = Objects.requireNonNull(AppInfo.getActiveProject());
		DomainFolder root = activeProject.getProjectData().getRootFolder();
		importerService.importFile(root, file);
	}

	@AutoServiceConsumed
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionImportMissingModule != null) {
				consoleService.addResolutionAction(actionImportMissingModule);
			}
			if (actionMapMissingModule != null) {
				consoleService.addResolutionAction(actionMapMissingModule);
			}
		}
	}

	protected void dispose() {
		if (consoleService != null) {
			if (actionImportMissingModule != null) {
				consoleService.removeResolutionAction(actionImportMissingModule);
			}
			if (actionMapMissingModule != null) {
				consoleService.removeResolutionAction(actionMapMissingModule);
			}
		}

		blockChooserDialog.dispose();
		moduleProposalDialog.dispose();
		sectionProposalDialog.dispose();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected boolean isFilterSectionsByModules() {
		return filterSectionsByModules;
	}

	void modulesPanelContextChanged() {
		myActionContext = modulesPanel.getActionContext();
		if (isFilterSectionsByModules()) {
			sectionsPanel.reload();
		}
		contextChanged();
	}

	void legacyModulesPanelContextChanged() {
		myActionContext = legacyModulesPanel.getActionContext();
		if (isFilterSectionsByModules()) {
			legacySectionsPanel.loadSections();
		}
		contextChanged();
	}

	void sectionsPanelContextChanged() {
		myActionContext = sectionsPanel.getActionContext();
		contextChanged();
	}

	void legacySectionsPanelContextChanged() {
		myActionContext = legacySectionsPanel.getActionContext();
		contextChanged();
	}

	protected void buildMainPanel() {
		mainPanel.setContinuousLayout(true);

		modulesPanel = new DebuggerModulesPanel(this);
		mainPanel.setLeftComponent(modulesPanel);
		legacyModulesPanel = new DebuggerLegacyModulesPanel(this);

		sectionsPanel = new DebuggerSectionsPanel(this);
		mainPanel.setRightComponent(sectionsPanel);
		legacySectionsPanel = new DebuggerLegacySectionsPanel(this);

		mainPanel.setResizeWeight(0.5);
	}

	protected void createActions() {
		actionMapIdentically = MapIdenticallyAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && current.getTrace() != null)
				.onAction(this::activatedMapIdentically)
				.buildAndInstallLocal(this);
		actionMapManually = MapManuallyAction.builder(plugin)
				.enabled(true)
				.onAction(this::activatedMapManually)
				.buildAndInstallLocal(this);
		actionMapModules = MapModulesAction.builder(plugin)
				.enabledWhen(ctx -> isContextHasModules(ctx) && isContextNotForcedSingle(ctx))
				.popupWhen(ctx -> isContextHasModules(ctx) && isContextNotForcedSingle(ctx))
				.onAction(this::activatedMapModules)
				.buildAndInstall(tool);
		actionMapModuleTo = MapModuleToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && getSelectedModules(ctx).size() == 1)
				.popupWhen(ctx -> currentProgram != null && getSelectedModules(ctx).size() == 1)
				.onAction(this::activatedMapModuleTo)
				.buildAndInstall(tool);
		actionMapSections = MapSectionsAction.builder(plugin)
				.enabledWhen(ctx -> isContextHasSections(ctx) && isContextNotForcedSingle(ctx))
				.popupWhen(ctx -> isContextHasSections(ctx) && isContextNotForcedSingle(ctx))
				.onAction(this::activatedMapSections)
				.buildAndInstall(tool);
		actionMapSectionTo = MapSectionToAction.builder(plugin)
				.enabledWhen(
					ctx -> currentProgram != null && getSelectedSections(ctx, false).size() == 1)
				.popupWhen(
					ctx -> currentProgram != null && getSelectedSections(ctx, false).size() == 1)
				.onAction(this::activatedMapSectionTo)
				.buildAndInstall(tool);
		actionMapSectionsTo = MapSectionsToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && isContextSectionsOfOneModule(ctx))
				.popupWhen(ctx -> currentProgram != null && isContextSectionsOfOneModule(ctx))
				.onAction(this::activatedMapSectionsTo)
				.buildAndInstall(tool);

		actionAutoMap = AutoMapAction.builder(plugin)
				.onActionStateChanged(this::changedAutoMapSpec)
				.buildAndInstallLocal(this);
		actionAutoMap.setCurrentActionStateByUserData(defaultAutoMapSpec);

		actionImportMissingModule = ImportMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedImportMissingModule)
				.build();
		actionMapMissingModule = MapMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedMapMissingModule)
				.build();

		actionSelectAddresses = new SelectAddressesAction();
		actionImportFromFileSystem = new ImportFromFileSystemAction();
		actionShowSectionsTable = ShowSectionsTableAction.builder(plugin)
				.onAction(this::toggledShowSectionsTable)
				.selected(showSectionsTable)
				.buildAndInstallLocal(this);
		actionFilterSectionsByModules = FilterAction.builder(plugin)
				.description("Filter sections to those in selected modules")
				.helpLocation(new HelpLocation(plugin.getName(), "filter_by_module"))
				.onAction(this::toggledFilter)
				.buildAndInstallLocal(this);
		actionSelectCurrent = SelectRowsAction.builder(plugin)
				.enabledWhen(ctx -> current.getTrace() != null)
				.description("Select modules and sections by dynamic selection")
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);

		contextChanged();
	}

	private boolean isContextHasModules(ActionContext context) {
		return !getSelectedModules(context).isEmpty();
	}

	private boolean isContextHasSections(ActionContext context) {
		return !getSelectedSections(context, false).isEmpty();
	}

	private boolean isContextNonEmpty(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return !ctx.getSelectedModules().isEmpty();
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return !ctx.getSelectedSections(false).isEmpty();
		}
		if (context instanceof DebuggerObjectActionContext ctx) {
			return !ctx.getObjectValues().isEmpty();
		}
		return false;
	}

	private boolean isContextNotForcedSingle(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return !ctx.isForcedSingle();
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return !ctx.isForcedSingle();
		}
		return true;
	}

	private boolean isContextSectionsOfOneModule(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, false);
		if (sel == null || sel.isEmpty()) {
			return false;
		}
		try {
			return sel.stream().map(TraceSection::getModule).distinct().count() == 1;
		}
		catch (Exception e) {
			Msg.error(this, "Could not check section selection context: " + e);
			return false;
		}
	}

	private void activatedMapIdentically(ActionContext ignored) {
		if (currentProgram == null || current.getTrace() == null) {
			return;
		}
		try {
			staticMappingService.addIdentityMapping(current.getTrace(), currentProgram,
				Lifespan.nowOn(traceManager.getCurrentSnap()), true);
		}
		catch (TraceConflictedMappingException e) {
			Msg.showError(this, null, "Map Identically", e.getMessage());
		}
	}

	private void activatedMapManually(ActionContext ignored) {
		ComponentProvider provider =
			tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_MAPPINGS);
		if (provider != null) {
			tool.showComponentProvider(provider, true);
			return;
		}
		try {
			tool.addPlugin(DebuggerStaticMappingPlugin.class.getName());
		}
		catch (PluginException e) {
			Msg.showError(this, mainPanel, MapManuallyAction.NAME,
				"DebuggerStaticMappingPlugin could not be enabled", e);
			return;
		}
		provider = tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_MAPPINGS);
		assert provider != null;
		tool.showComponentProvider(provider, true);
	}

	private void activatedMapModules(ActionContext context) {
		Set<TraceModule> sel = getSelectedModules(context);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapModules(sel);
	}

	private void activatedMapModuleTo(ActionContext context) {
		Set<TraceModule> sel = getSelectedModules(context);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapModuleTo(sel.iterator().next());
	}

	private void activatedMapSections(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, true);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSections(sel);
	}

	private void activatedMapSectionsTo(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, true);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSectionsTo(sel);
	}

	private void activatedMapSectionTo(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, false);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapSectionTo(sel.iterator().next());
	}

	private void changedAutoMapSpec(ActionState<AutoMapSpec> newState, EventTrigger trigger) {
		doSetAutoMapSpec(newState.getUserData());
	}

	private void doSetAutoMapSpec(AutoMapSpec autoMapSpec) {
		if (this.autoMapSpec == autoMapSpec) {
			return;
		}
		removeOldTraceListener();
		this.autoMapSpec = autoMapSpec;
		addNewTraceListener();
	}

	private void activatedImportMissingModule(DebuggerMissingModuleActionContext context) {
		if (importerService == null) {
			Msg.error(this, "Import service is not present");
		}
		importModuleFromFileSystem(context.getModule());
	}

	private void activatedMapMissingModule(DebuggerMissingModuleActionContext context) {
		mapModuleTo(context.getModule());
	}

	private void toggledShowSectionsTable(ActionContext ignored) {
		setShowSectionsTable(actionShowSectionsTable.isSelected());
	}

	public void setShowSectionsTable(boolean showSectionsTable) {
		if (this.showSectionsTable == showSectionsTable) {
			return;
		}
		doSetShowSectionsTable(showSectionsTable);
	}

	protected void doSetShowSectionsTable(boolean showSectionsTable) {
		this.showSectionsTable = showSectionsTable;
		actionShowSectionsTable.setSelected(showSectionsTable);
		mainPanel.setDividerSize(showSectionsTable ? defaultDividerSize : 0);
		sectionsPanel.setVisible(showSectionsTable);
		legacySectionsPanel.setVisible(showSectionsTable);
		mainPanel.resetToPreferredSizes();
	}

	private void toggledFilter(ActionContext ignored) {
		setFilterSectionsByModules(actionFilterSectionsByModules.isSelected());
	}

	public void setFilterSectionsByModules(boolean filterSectionsByModules) {
		if (this.filterSectionsByModules == filterSectionsByModules) {
			return;
		}
		doSetFilterSectionsByModules(filterSectionsByModules);
	}

	protected void doSetFilterSectionsByModules(boolean filterSectionsByModules) {
		this.filterSectionsByModules = filterSectionsByModules;
		actionFilterSectionsByModules.setSelected(filterSectionsByModules);
		sectionsPanel.setFilteredBySelectedModules(filterSectionsByModules);
		legacySectionsPanel.setFilteredBySelectedModules(filterSectionsByModules);
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || current.getTrace() == null) {
			return;
		}

		ProgramSelection progSel = listingService.getCurrentSelection();
		TraceModuleManager moduleManager = current.getTrace().getModuleManager();
		if (progSel != null && !progSel.isEmpty()) {
			long snap = traceManager.getCurrentSnap();
			Set<TraceModule> modSel = new HashSet<>();
			Set<TraceSection> sectionSel = new HashSet<>();
			for (AddressRange range : progSel) {
				for (TraceModule module : moduleManager
						.getModulesIntersecting(Lifespan.at(snap), range)) {
					if (module.getSections().isEmpty()) {
						modSel.add(module);
					}
				}
				for (TraceSection section : moduleManager
						.getSectionsIntersecting(Lifespan.at(snap), range)) {
					sectionSel.add(section);
					modSel.add(section.getModule());
				}
			}
			setSelectedModules(modSel);
			setSelectedSections(sectionSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			Address address = progLoc.getAddress();
			Set<TraceSection> sectionsAt =
				Set.copyOf(moduleManager.getSectionsAt(traceManager.getCurrentSnap(), address));
			if (!sectionsAt.isEmpty()) {
				Set<TraceModule> modulesAt =
					sectionsAt.stream().map(TraceSection::getModule).collect(Collectors.toSet());
				setSelectedModules(modulesAt);
				setSelectedSections(sectionsAt);
				return;
			}
			TraceModule bestModule = null;
			for (TraceModule module : moduleManager
					.getLoadedModules(traceManager.getCurrentSnap())) {
				Address base = module.getBase();
				if (base == null || base.getAddressSpace() != address.getAddressSpace()) {
					continue;
				}
				if (bestModule == null) {
					bestModule = module;
					continue;
				}
				if (base.compareTo(address) > 0) {
					continue;
				}
				if (base.compareTo(bestModule.getBase()) <= 0) {
					continue;
				}
				bestModule = module;
			}
			if (bestModule.getSections().isEmpty()) {
				setSelectedModules(Set.of(bestModule));
				return;
			}
		}
	}

	protected void promptModuleProposal(Collection<ModuleMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Modules",
				"Could not formulate a proposal for any selected module." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<ModuleMapEntry> adjusted =
			moduleProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapModulesBackgroundCommand(staticMappingService, adjusted), current.getTrace());
	}

	protected void mapModules(Set<TraceModule> modules) {
		if (staticMappingService == null) {
			return;
		}
		Map<TraceModule, ModuleMapProposal> map = staticMappingService.proposeModuleMaps(modules,
			List.of(programManager.getAllOpenPrograms()));
		Collection<ModuleMapEntry> proposal = MapProposal.flatten(map.values());
		promptModuleProposal(proposal);
	}

	protected void mapModuleTo(TraceModule module) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		ModuleMapProposal proposal = staticMappingService.proposeModuleMap(module, program);
		Map<TraceModule, ModuleMapEntry> map = proposal.computeMap();
		promptModuleProposal(map.values());
	}

	protected void promptSectionProposal(Collection<SectionMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Sections",
				"Could not formulate a proposal for any selected section." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<SectionMapEntry> adjusted =
			sectionProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapSectionsBackgroundCommand(staticMappingService, adjusted), current.getTrace());
	}

	protected void mapSections(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		Map<?, SectionMapProposal> map = staticMappingService.proposeSectionMaps(modules,
			List.of(programManager.getAllOpenPrograms()));
		Collection<SectionMapEntry> proposal = MapProposal.flatten(map.values());
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionsTo(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		if (modules.size() != 1) {
			return;
		}
		TraceModule module = modules.iterator().next();
		SectionMapProposal map = staticMappingService.proposeSectionMap(module, program);
		Collection<SectionMapEntry> proposal = map.computeMap().values();
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionTo(TraceSection section) {
		if (staticMappingService == null) {
			return;
		}
		ProgramLocation location = currentLocation;
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return;
		}
		SectionMapProposal map =
			staticMappingService.proposeSectionMap(section, location.getProgram(), block);
		promptSectionProposal(map.computeMap().values());
	}

	protected Set<MemoryBlock> collectBlocksInOpenPrograms() {
		Set<MemoryBlock> result = new HashSet<>();
		for (Program p : programManager.getAllOpenPrograms()) {
			if (p instanceof Trace) {
				continue;
			}
			result.addAll(List.of(p.getMemory().getBlocks()));
		}
		return result;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setProgram(Program program) {
		currentProgram = program;
		String name;
		if (program != null) {
			DomainFile df = program.getDomainFile();
			if (df != null) {
				name = df.getName();
			}
			else {
				name = program.getName();
			}
		}
		else {
			name = "...";
		}
		actionMapModuleTo.getPopupMenuData().setMenuItemName(MapModuleToAction.NAME_PREFIX + name);
		actionMapSectionsTo.getPopupMenuData()
				.setMenuItemName(MapSectionsToAction.NAME_PREFIX + name);
	}

	public static MemoryBlock computeBlock(ProgramLocation location) {
		if (location == null) {
			return null;
		}
		Program program = location.getProgram();
		if (program == null) {
			return null;
		}
		Address addr = location.getAddress();
		if (addr == null) {
			return null;
		}
		return program.getMemory().getBlock(addr);
	}

	public static String computeBlockName(ProgramLocation location) {
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return "...";
		}
		Program program = location.getProgram();
		String name = program.getName();
		DomainFile df = program.getDomainFile();
		if (df != null) {
			name = df.getName();
		}
		return name + ":" + block.getName();
	}

	public void setLocation(ProgramLocation location) {
		currentLocation = location;
		String name = MapSectionToAction.NAME_PREFIX + computeBlockName(location);
		actionMapSectionTo.getPopupMenuData().setMenuItemName(name);
	}

	public void programOpened(Program program) {
		// TODO: Debounce this?
		cueAutoMap = true;
		doCuedAutoMap();
	}

	public void programClosed(Program program) {
		if (currentProgram == program) {
			currentProgram = null;
		}
	}

	protected void addNewTraceListener() {
		if (current.getTrace() != null && autoMapSpec != null) {
			forMappingListener = new ForMappingTraceListener(autoMapSpec);
			current.getTrace().addListener(forMappingListener);
		}
	}

	protected void removeOldTraceListener() {
		if (forMappingListener != null) {
			if (current.getTrace() != null) {
				current.getTrace().removeListener(forMappingListener);
			}
			forMappingListener = null;
		}
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		boolean changeTrace = current.getTrace() != coordinates.getTrace();
		if (changeTrace) {
			myActionContext = null;
			removeOldTraceListener();
		}
		current = coordinates;
		if (changeTrace) {
			addNewTraceListener();
		}

		if (Trace.isLegacy(coordinates.getTrace())) {
			modulesPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			sectionsPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacyModulesPanel.coordinatesActivated(coordinates);
			legacySectionsPanel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), legacyModulesPanel) == -1) {
				mainPanel.remove(modulesPanel);
				mainPanel.remove(sectionsPanel);
				mainPanel.setLeftComponent(legacyModulesPanel);
				mainPanel.setRightComponent(legacySectionsPanel);
				mainPanel.validate();
			}
		}
		else {
			legacyModulesPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacySectionsPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			modulesPanel.coordinatesActivated(coordinates);
			sectionsPanel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), modulesPanel) == -1) {
				mainPanel.remove(legacyModulesPanel);
				mainPanel.remove(legacySectionsPanel);
				mainPanel.setLeftComponent(modulesPanel);
				mainPanel.setRightComponent(sectionsPanel);
				mainPanel.validate();
			}
		}

		contextChanged();

		if (coordinates.getTarget() instanceof TraceRecorderTarget) {
			// HACK while TraceRecorderTarget is still around
			cueAutoMap = true;
		}
		doCuedAutoMap();
	}

	private void doCuedAutoMap() {
		if (cueAutoMap) {
			cueAutoMap = false;
			Trace trace = current.getTrace();
			if (autoMapSpec != null && trace != null) {
				autoMapSpec.runTask(tool, trace);
			}
		}
	}

	public void setSelectedModules(Set<TraceModule> sel) {
		if (Trace.isLegacy(current.getTrace())) {
			legacyModulesPanel.setSelectedModules(sel);
		}
		else {
			modulesPanel.setSelectedModules(sel);
		}
	}

	public void setSelectedSections(Set<TraceSection> sel) {
		if (Trace.isLegacy(current.getTrace())) {
			legacySectionsPanel.setSelectedSections(sel);
		}
		else {
			sectionsPanel.setSelectedSections(sel);
		}
	}

	private DataTreeDialog getProgramChooserDialog() {

		DomainFileFilter filter = df -> Program.class.isAssignableFrom(df.getDomainObjectClass());

		return new DataTreeDialog(null, "Map Module to Program", DataTreeDialog.OPEN, filter);
	}

	public DomainFile askProgram(Program program) {
		DataTreeDialog dialog = getProgramChooserDialog();
		if (program != null) {
			dialog.selectDomainFile(program.getDomainFile());
		}
		tool.showDialog(dialog);
		return dialog.getDomainFile();
	}

	public Entry<Program, MemoryBlock> askBlock(TraceSection section, Program program,
			MemoryBlock block) {
		if (programManager == null) {
			Msg.warn(this, "No program manager!");
			return null;
		}
		return blockChooserDialog.chooseBlock(getTool(), section,
			List.of(programManager.getAllOpenPrograms()));
	}

	public void setAutoMapSpec(AutoMapSpec spec) {
		actionAutoMap.setCurrentActionStateByUserData(spec);
	}

	public AutoMapSpec getAutoMapSpec() {
		return autoMapSpec;
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		actionAutoMap.setCurrentActionStateByUserData(autoMapSpec);
		doSetFilterSectionsByModules(filterSectionsByModules);
		doSetShowSectionsTable(showSectionsTable);
	}
}
