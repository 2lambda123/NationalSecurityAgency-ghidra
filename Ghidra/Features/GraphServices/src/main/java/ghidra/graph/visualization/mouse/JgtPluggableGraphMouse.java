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
package ghidra.graph.visualization.mouse;

import java.awt.event.InputEvent;

import org.jungrapht.visualization.control.*;

import docking.DockingUtils;
import ghidra.graph.visualization.DefaultGraphDisplay;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * Pluggable graph mouse for jungrapht
 */
public class JgtPluggableGraphMouse extends DefaultGraphMouse<AttributedVertex, AttributedEdge> {

	private DefaultGraphDisplay graphDisplay;

	// TODO we should not need the graph display for any mouse plugins, but the API is net yet
	//      robust enough to communicate fully without it
	public JgtPluggableGraphMouse(DefaultGraphDisplay graphDisplay) {
		super(DefaultGraphMouse.<AttributedVertex, AttributedEdge> builder());
		this.graphDisplay = graphDisplay;
	}

	@Override
	public void loadPlugins() {

		//
		// Note: the order of these additions matters, as an event will flow to each plugin until
		//       it is handled.
		//

		// edge 
		add(new JgtEdgeNavigationPlugin<AttributedVertex, AttributedEdge>());

		add(new JgtVertexFocusingPlugin<AttributedVertex, AttributedEdge>(graphDisplay));

		// scaling
		add(new ScalingGraphMousePlugin(new CrossoverScalingControl(), 0, in, out));

		// the grab/pan feature
		add(new JgtTranslatingPlugin<AttributedVertex, AttributedEdge>());

		add(new SelectingGraphMousePlugin<AttributedVertex, AttributedEdge>(
			InputEvent.BUTTON1_DOWN_MASK,
			0,
			DockingUtils.CONTROL_KEY_MODIFIER_MASK));

		// cursor cleanup
		add(new JgtCursorRestoringPlugin<AttributedVertex, AttributedEdge>());

		setPluginsLoaded();
	}
}
