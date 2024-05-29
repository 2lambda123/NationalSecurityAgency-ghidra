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
package ghidra.app.plugin.core.symboltree;

import java.util.*;

import javax.swing.tree.TreePath;

import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class SymbolTreeActionContext extends ProgramSymbolActionContext {

	private TreePath[] selectionPaths;

	SymbolTreeActionContext(SymbolTreeProvider provider, Program program, SymbolGTree tree,
			TreePath[] selectionPaths) {
		super(provider, program, getSymbols(selectionPaths), tree);
		this.selectionPaths = selectionPaths;
	}

	public SymbolTreeProvider getSymbolTreeProvider() {
		return (SymbolTreeProvider) getComponentProvider();
	}

	public SymbolGTree getSymbolTree() {
		return (SymbolGTree) getContextObject();
	}

	public TreePath[] getSelectedSymbolTreePaths() {
		return selectionPaths;
	}

	public TreePath getSelectedPath() {
		if (selectionPaths.length == 1) {
			return selectionPaths[0];
		}
		return null;
	}

	/**
	 * Returns a symbol tree node if there is a single node selected and it is a symbol tree node.
	 * Otherwise, null is returned.
	 * @return the selected node or null
	 */
	public SymbolTreeNode getSelectedNode() {
		if (selectionPaths != null && selectionPaths.length == 1) {
			Object object = selectionPaths[0].getLastPathComponent();
			if (object instanceof SymbolTreeNode node) {
				return node;
			}
		}
		return null;
	}

	/**
	 * Returns all selected {@link SymbolNode}s or an empty list.
	 * @return all selected {@link SymbolNode}s or an empty list.
	 */
	public List<SymbolNode> getSelectedSymbolNodes() {
		if (selectionPaths == null) {
			return List.of();
		}

		List<SymbolNode> symbols = new ArrayList<>();
		for (TreePath treePath : selectionPaths) {
			Object object = treePath.getLastPathComponent();
			if (object instanceof SymbolNode) {
				symbols.add((SymbolNode) object);
			}
		}
		return symbols;
	}

	private static List<Symbol> getSymbols(TreePath[] selectionPaths) {
		if (selectionPaths == null) {
			return Collections.emptyList();
		}

		List<Symbol> symbols = new ArrayList<>();
		for (TreePath treePath : selectionPaths) {
			Object object = treePath.getLastPathComponent();
			if (object instanceof SymbolNode) {
				SymbolNode symbolNode = (SymbolNode) object;
				symbols.add(symbolNode.getSymbol());
			}
		}
		return symbols;
	}
}
