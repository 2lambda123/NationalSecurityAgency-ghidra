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

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.Objects;

import javax.swing.*;

import org.apache.commons.lang3.ArrayUtils;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.modules.ModuleRow;
import ghidra.app.plugin.core.debug.stack.UnwindStackCommand;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.HelpLocation;

public class DebuggerStackProvider extends ComponentProviderAdapter {

	public interface UnwindStackAction {
		String NAME = "Unwind from frame 0";
		String DESCRIPTION = "Unwind the stack, placing frames in the dynamic listing";
		String HELP_ANCHOR = "unwind_stack";
		KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_U, 0);

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, "Analysis", NAME)
					.keyBinding(KEY_STROKE)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		return true;
	}

	final DebuggerStackPlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	@AutoServiceConsumed // TODO: Add listener for mapping changes to refresh table
	DebuggerStaticMappingService mappingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	/*testing*/ DebuggerStackPanel panel;
	/*testing*/ DebuggerLegacyStackPanel legacyPanel;

	DockingAction actionUnwindStack;

	public DebuggerStackProvider(DebuggerStackPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_STACK, plugin.getName());
		this.plugin = plugin;
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle(DebuggerResources.TITLE_PROVIDER_STACK);
		setIcon(DebuggerResources.ICON_PROVIDER_STACK);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.LEFT);
		createActions();

		setVisible(true);
	}

	protected void buildMainPanel() {
		panel = new DebuggerStackPanel(this);
		mainPanel.add(panel);
		legacyPanel = new DebuggerLegacyStackPanel(plugin, this);
	}

	protected void createActions() {
		actionUnwindStack = UnwindStackAction.builder(plugin)
				.enabledWhen(ctx -> current.getTrace() != null)
				.onAction(this::activatedUnwindStack)
				.buildAndInstall(tool);
	}

	private void activatedUnwindStack(ActionContext ignored) {
		new UnwindStackCommand(tool, current).run(tool, current.getTrace());
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		final ActionContext context;
		if (Trace.isLegacy(current.getTrace())) {
			context = legacyPanel.getActionContext();
		}
		else {
			context = panel.getActionContext();
		}
		if (context != null) {
			return context;
		}
		return super.getActionContext(event);
	}

	protected String computeSubTitle() {
		TraceThread curThread = current.getThread();
		return curThread == null ? "" : curThread.getName();
	}

	protected void updateSubTitle() {
		setSubTitle(computeSubTitle());
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		if (Trace.isLegacy(coordinates.getTrace())) {
			panel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacyPanel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), legacyPanel) == -1) {
				mainPanel.remove(panel);
				mainPanel.add(legacyPanel);
				mainPanel.validate();
			}
		}
		else {
			legacyPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			panel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), panel) == -1) {
				mainPanel.remove(legacyPanel);
				mainPanel.add(panel);
				mainPanel.validate();
			}
		}
		updateSubTitle();
	}

	public void traceClosed(Trace trace) {
		if (trace == current.getTrace()) {
			panel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacyPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
		}
	}

	public Function getFunction(Address pc) {
		if (pc == null) {
			return null;
		}
		if (mappingService == null) {
			return null;
		}
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			return null;
		}
		TraceLocation dloc = new DefaultTraceLocation(curThread.getTrace(),
			curThread, Lifespan.at(current.getSnap()), pc);
		ProgramLocation sloc = mappingService.getOpenMappedLocation(dloc);
		if (sloc == null) {
			return null;
		}
		return sloc.getProgram().getFunctionManager().getFunctionContaining(sloc.getAddress());
	}

	public String getModule(Address pc) {
		if (pc == null) {
			return null;
		}
		Trace trace = current.getTrace();
		if (trace == null) {
			return null;
		}
		for (TraceModule module : trace.getModuleManager().getModulesAt(current.getSnap(), pc)) {
			// Just take the first
			return ModuleRow.computeShortName(module.getName());
		}
		return null;
	}
}
