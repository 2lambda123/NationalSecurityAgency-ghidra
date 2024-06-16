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
package ghidra.app.nav;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;

import generic.theme.GColor;

public class DecoratorPanel extends JPanel {

	private static final Color DISCONNECTED = new GColor("color.border.provider.disconnected");

	public DecoratorPanel(JComponent component, boolean isConnected) {
		setLayout(new BorderLayout());
		add(component);
		setConnected(isConnected);
	}

	public void setConnected(boolean isConnected) {
		if (!isConnected) {
			setBorder(BorderFactory.createLineBorder(DISCONNECTED, 2));
		}
		else {
			setBorder(BorderFactory.createEmptyBorder());
		}
	}
}
