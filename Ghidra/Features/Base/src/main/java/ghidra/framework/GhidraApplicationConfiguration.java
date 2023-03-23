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
package ghidra.framework;

import docking.DockingErrorDisplay;
import docking.DockingWindowManager;
import docking.framework.ApplicationInformationDisplayFactory;
import docking.framework.SplashScreen;
import docking.widgets.PopupKeyStorePasswordProvider;
import generic.theme.ApplicationThemeManager;
import ghidra.docking.util.LookAndFeelUtils;
import ghidra.formats.gfilesystem.crypto.CryptoProviders;
import ghidra.formats.gfilesystem.crypto.PopupGUIPasswordProvider;
import ghidra.framework.main.GhidraApplicationInformationDisplayFactory;
import ghidra.framework.main.UserAgreementDialog;
import ghidra.framework.preferences.Preferences;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.ErrorDisplay;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitorAdapter;

public class GhidraApplicationConfiguration extends HeadlessGhidraApplicationConfiguration {

	private static final String USER_AGREEMENT_PROPERTY_NAME = "USER_AGREEMENT";
	private boolean showSplashScreen = true;

	@Override
	public boolean isHeadless() {
		return false;
	}

	@Override
	protected void initializeApplication() {
		ApplicationThemeManager.initialize();
		LookAndFeelUtils.performPlatformSpecificFixups();

		if (showSplashScreen) {
			showUserAgreement();
			SplashScreen.showSplashScreen();
			this.monitor = new StatusReportingTaskMonitor();
		}

		super.initializeApplication();

		ApplicationKeyManagerFactory
				.setKeyStorePasswordProvider(new PopupKeyStorePasswordProvider());
		CryptoProviders.getInstance().registerCryptoProvider(new PopupGUIPasswordProvider());
	}

	private static void showUserAgreement() {
		String value = Preferences.getProperty(USER_AGREEMENT_PROPERTY_NAME);
		if ("ACCEPT".equals(value)) {
			return;
		}

		SystemUtilities.runSwingNow(() -> {
			UserAgreementDialog dialog = new UserAgreementDialog(true, true);
			DockingWindowManager.showDialog(null, dialog);
		});

		// if we get here, then the user has accepted (if not, the system would have exited)
		Preferences.setProperty(USER_AGREEMENT_PROPERTY_NAME, "ACCEPT");
	}

	@Override
	public void installStaticFactories() {
		super.installStaticFactories();
		PluggableServiceRegistry.registerPluggableService(
			ApplicationInformationDisplayFactory.class,
			new GhidraApplicationInformationDisplayFactory());
	}

	public void setShowSplashScreen(boolean b) {
		showSplashScreen = b;
	}

	@Override
	public ErrorDisplay getErrorDisplay() {
		return new DockingErrorDisplay();
	}

	private static class StatusReportingTaskMonitor extends TaskMonitorAdapter {
		@Override
		public synchronized void setCancelEnabled(boolean enable) {
			// Not permitted
		}

		@Override
		public void setMessage(String message) {
			SplashScreen.updateSplashScreenStatus(message);
		}
	}

}
