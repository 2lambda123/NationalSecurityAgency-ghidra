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
package docking.actions;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.Action;
import javax.swing.KeyStroke;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.Predicate;
import org.apache.commons.collections4.map.LazyMap;

import com.google.common.collect.Iterators;

import docking.*;
import docking.action.*;
import docking.tool.util.DockingToolConstants;
import ghidra.framework.options.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import util.CollectionUtils;

/**
 * An class to manage actions registered with the tool
 */
public class ToolActions implements DockingToolActions, PropertyChangeListener {

	private ActionToGuiHelper actionGuiHelper;

	/*
	 	Map of Maps of Sets
	 	
	 	Owner Name -> 
	 		Action Name -> Set of Actions
	 */
	private Map<String, Map<String, Set<DockingActionIf>>> actionsByNameByOwner = LazyMap.lazyMap(
		new HashMap<>(), () -> LazyMap.lazyMap(new HashMap<>(), () -> new HashSet<>()));

	private Map<String, SharedStubKeyBindingAction> sharedActionMap = new HashMap<>();

	private ToolOptions keyBindingOptions;
	private DockingTool dockingTool;
	private KeyBindingsManager keyBindingsManager;

	/**
	 * Construct an ActionManager
	 * 
	 * @param tool tool using this ActionManager
	 * @param actionToGuiHelper the class that takes actions and maps them to GUI widgets
	 */
	public ToolActions(DockingTool tool, ActionToGuiHelper actionToGuiHelper) {
		this.dockingTool = tool;
		this.actionGuiHelper = actionToGuiHelper;
		this.keyBindingsManager = new KeyBindingsManager(tool);
		this.keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		createReservedKeyBindings();
		SharedActionRegistry.installSharedActions(tool, this);
	}

	private void createReservedKeyBindings() {
		KeyBindingAction keyBindingAction = new KeyBindingAction(this);
		keyBindingsManager.addReservedAction(keyBindingAction,
			ReservedKeyBindings.UPDATE_KEY_BINDINGS_KEY);

		keyBindingsManager.addReservedAction(new HelpAction(false, ReservedKeyBindings.HELP_KEY1));
		keyBindingsManager.addReservedAction(new HelpAction(false, ReservedKeyBindings.HELP_KEY2));
		keyBindingsManager.addReservedAction(
			new HelpAction(true, ReservedKeyBindings.HELP_INFO_KEY));

		// these are diagnostic
		if (SystemUtilities.isInDevelopmentMode()) {
			keyBindingsManager.addReservedAction(new ShowFocusInfoAction());
			keyBindingsManager.addReservedAction(new ShowFocusCycleAction());
		}
	}

	public void dispose() {
		actionsByNameByOwner.clear();
		sharedActionMap.clear();
		keyBindingsManager.dispose();
	}

	private void addActionToMap(DockingActionIf action) {

		Set<DockingActionIf> actions = getActionStorage(action);
		KeyBindingUtils.assertSameDefaultKeyBindings(action, actions);
		actions.add(action);
	}

	/**
	 * Add an action that works specifically with a component provider. 
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	@Override
	public synchronized void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		checkForAlreadyAddedAction(provider, action);

		action.addPropertyChangeListener(this);
		addActionToMap(action);
		initializeKeyBinding(provider, action);
		actionGuiHelper.addLocalAction(provider, action);
	}

	@Override
	public synchronized void addGlobalAction(DockingActionIf action) {
		checkForAlreadyAddedAction(null, action);

		action.addPropertyChangeListener(this);
		addActionToMap(action);
		initializeKeyBinding(null, action);
		actionGuiHelper.addToolAction(action);
	}

	private void initializeKeyBinding(ComponentProvider provider, DockingActionIf action) {

		KeyBindingType type = action.getKeyBindingType();
		if (!type.supportsKeyBindings()) {
			return;
		}

		if (type.isShared()) {
			installSharedKeyBinding(provider, action);
			return;
		}

		KeyStroke ks = action.getKeyBinding();
		String description = "Keybinding for " + action.getFullName();
		keyBindingOptions.registerOption(action.getFullName(), OptionType.KEYSTROKE_TYPE, ks, null,
			description);
		KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
		if (!Objects.equals(ks, newKs)) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
		}

		keyBindingsManager.addAction(provider, action);
	}

	private void installSharedKeyBinding(ComponentProvider provider, DockingActionIf action) {
		String name = action.getName();
		KeyStroke defaultKeyStroke = action.getKeyBinding();

		// get or create the stub to which we will add the action
		SharedStubKeyBindingAction stub = sharedActionMap.computeIfAbsent(name, key -> {

			SharedStubKeyBindingAction newStub =
				new SharedStubKeyBindingAction(name, keyBindingOptions);
			registerStub(newStub, defaultKeyStroke);
			return newStub;
		});

		stub.addClientAction(action);

		if (!(action instanceof AutoGeneratedDockingAction)) {
			// Auto-generated actions are temporary and should not receive key events
			keyBindingsManager.addAction(provider, action);
		}
	}

	private void registerStub(SharedStubKeyBindingAction stub, KeyStroke defaultKeyStroke) {
		stub.addPropertyChangeListener(this);
		String description = "Keybinding for Stub action: " + stub.getFullName();
		keyBindingOptions.registerOption(stub.getFullName(), OptionType.KEYSTROKE_TYPE,
			defaultKeyStroke, null, description);
		keyBindingsManager.addAction(null, stub);
	}

	/**
	 * Removes the given action from the tool
	 * @param action the action to be removed.
	 */
	@Override
	public synchronized void removeGlobalAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		actionGuiHelper.removeToolAction(action);
		dispose(action);
	}

	private void dispose(DockingActionIf action) {
		try {
			action.dispose();
		}
		catch (Throwable t) {
			Msg.error(this, "Exception disposing action '" + action.getFullName() + "'", t);
		}
	}

	@Override
	public synchronized void removeActions(String owner) {

		// remove from the outer map first, to prevent concurrent modification exceptions
		Map<String, Set<DockingActionIf>> toCleanup = actionsByNameByOwner.remove(owner);
		if (toCleanup == null) {
			return; // no actions registered for this owner
		}

		//@formatter:off
		toCleanup.values()
			.stream()
			.flatMap(set -> set.stream())
			.forEach(action -> removeGlobalAction(action))
			;
		//@formatter:on
	}

	private void checkForAlreadyAddedAction(ComponentProvider provider, DockingActionIf action) {
		if (getActionStorage(action).contains(action)) {
			String providerString =
				provider == null ? "Action: " : "Provider " + provider.getName() + " - action: ";
			throw new AssertException("Cannot add the same action more than once. " +
				providerString + action.getFullName());
		}
	}

	/**
	 * Get all actions for the given owner
	 * @param owner owner of the actions
	 * @return array of actions; zero length array is returned if no
	 * action exists with the given name
	 */
	@Override
	public synchronized Set<DockingActionIf> getActions(String owner) {

		Set<DockingActionIf> result = new HashSet<>();
		Map<String, Set<DockingActionIf>> actionsByName = actionsByNameByOwner.get(owner);
		for (Set<DockingActionIf> actions : actionsByName.values()) {
			result.addAll(actions);
		}

		if (SharedStubKeyBindingAction.SHARED_OWNER.equals(owner)) {
			result.addAll(sharedActionMap.values());
		}

		return result;
	}

	/**
	 * Get a set of all actions in the tool
	 * 
	 * @return a new set of the existing actions
	 */
	@Override
	public synchronized Set<DockingActionIf> getAllActions() {

		Set<DockingActionIf> result = new HashSet<>();
		Collection<Map<String, Set<DockingActionIf>>> maps = actionsByNameByOwner.values();
		for (Map<String, Set<DockingActionIf>> actionsByName : maps) {
			for (Set<DockingActionIf> actions : actionsByName.values()) {
				result.addAll(actions);
			}
		}

		result.addAll(sharedActionMap.values());

		return result;
	}

	private Iterator<DockingActionIf> getAllActionsIterator() {

		// chain all items together, rather than copy the data
		Iterator<DockingActionIf> iterator = IteratorUtils.emptyIterator();
		Collection<Map<String, Set<DockingActionIf>>> maps = actionsByNameByOwner.values();
		for (Map<String, Set<DockingActionIf>> actionsByName : maps) {
			for (Set<DockingActionIf> actions : actionsByName.values()) {
				Iterator<DockingActionIf> next = actions.iterator();

				// Note: do not use apache commons here--the code below degrades exponentially
				//iterator = IteratorUtils.chainedIterator(iterator, next);
				iterator = Iterators.concat(iterator, next);
			}
		}

		return Iterators.concat(iterator, sharedActionMap.values().iterator());
	}

	/**
	 * Get the keybindings for each action so that they are still registered as being used; 
	 * otherwise the options will be removed because they are noted as not being used.
	 */
	public synchronized void restoreKeyBindings() {
		keyBindingOptions = dockingTool.getOptions(DockingToolConstants.KEY_BINDINGS);

		Iterator<DockingActionIf> it = getKeyBindingActionsIterator();
		for (DockingActionIf action : CollectionUtils.asIterable(it)) {
			KeyStroke ks = action.getKeyBinding();
			KeyStroke newKs = keyBindingOptions.getKeyStroke(action.getFullName(), ks);
			if (!Objects.equals(ks, newKs)) {
				action.setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
			}
		}
	}

	// return only actions that allow key bindings
	private Iterator<DockingActionIf> getKeyBindingActionsIterator() {
		Predicate<DockingActionIf> filter = a -> a.getKeyBindingType() == KeyBindingType.INDIVIDUAL;
		return IteratorUtils.filteredIterator(getAllActionsIterator(), filter);
	}

	/**
	 * Remove an action that works specifically with a component provider. 
	 * @param provider provider associated with the action
	 * @param action local action to the provider
	 */
	@Override
	public synchronized void removeLocalAction(ComponentProvider provider, DockingActionIf action) {
		action.removePropertyChangeListener(this);
		removeAction(action);
		keyBindingsManager.removeAction(action);
		actionGuiHelper.removeProviderAction(provider, action);
		dispose(action);
	}

	@Override
	public synchronized void removeActions(ComponentProvider provider) {
		Iterator<DockingActionIf> it = actionGuiHelper.getComponentActions(provider);

		// copy the data to avoid concurrent modification exceptions
		Set<DockingActionIf> set = CollectionUtils.asSet(it);
		for (DockingActionIf action : set) {
			removeLocalAction(provider, action);
		}
	}

	private void removeAction(DockingActionIf action) {

		keyBindingsManager.removeAction(action);

		getActionStorage(action).remove(action);
		if (!action.getKeyBindingType().isShared()) {
			return;
		}

		SharedStubKeyBindingAction stub = sharedActionMap.get(action.getName());
		if (stub != null) {
			stub.removeClientAction(action);
		}
	}

	private Set<DockingActionIf> getActionStorage(DockingActionIf action) {
		String owner = action.getOwner();
		String name = action.getName();
		return actionsByNameByOwner.get(owner).get(name);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (!evt.getPropertyName().equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			return;
		}

		DockingAction action = (DockingAction) evt.getSource();
		if (!action.getKeyBindingType().isManaged()) {
			// this reads unusually, but we need to notify the tool to rebuild its 'Window' menu 
			// in the case that this action is one of the tool's special actions
			keyBindingsChanged();
			return;
		}

		KeyBindingData newKeyBindingData = (KeyBindingData) evt.getNewValue();
		KeyStroke newKeyStroke = null;
		if (newKeyBindingData != null) {
			newKeyStroke = newKeyBindingData.getKeyBinding();
		}

		Options opt = dockingTool.getOptions(DockingToolConstants.KEY_BINDINGS);
		KeyStroke optKeyStroke = opt.getKeyStroke(action.getFullName(), null);
		if (newKeyStroke == null) {
			opt.removeOption(action.getFullName());
		}
		else if (!newKeyStroke.equals(optKeyStroke)) {
			opt.setKeyStroke(action.getFullName(), newKeyStroke);
			keyBindingsChanged();
		}
	}

	// triggered by a user-initiated action; called by propertyChange()
	private void keyBindingsChanged() {
		dockingTool.setConfigChanged(true);
		actionGuiHelper.keyBindingsChanged();
	}

	@Override
	public DockingActionIf getLocalAction(ComponentProvider provider, String actionName) {

		Iterator<DockingActionIf> it = actionGuiHelper.getComponentActions(provider);
		while (it.hasNext()) {
			DockingActionIf action = it.next();
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	public Action getAction(KeyStroke ks) {
		return keyBindingsManager.getDockingKeyAction(ks);
	}

	DockingActionIf getSharedStubKeyBindingAction(String name) {
		return sharedActionMap.get(name);
	}

}
