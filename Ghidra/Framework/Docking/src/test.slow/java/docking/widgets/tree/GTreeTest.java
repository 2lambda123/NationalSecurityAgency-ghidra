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
package docking.widgets.tree;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.filter.FilterOptions;
import docking.widgets.filter.TextFilterStrategy;
import docking.widgets.tree.support.GTreeFilter;

public class GTreeTest extends AbstractDockingTest {

	private JFrame frame;
	private GTree gTree;
	private int nodeIdCounter = 1;

	/**
	 * Test variable to easily control the filtering of test filters.
	 */
	private volatile boolean filterEnabled = true;

	@Before
	public void setUp() throws Exception {
		gTree = new GTree(new TestRootNode());

		frame = new JFrame("GTree Test");
		frame.getContentPane().add(gTree);
		frame.setSize(400, 400);
		frame.setVisible(true);

		waitForTree();
	}

	@After
	public void tearDown() throws Exception {
		gTree.dispose();
		frame.dispose();
	}

	@Test
	public void testFilterFromKeyStroke() {
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		GTreeNode node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		typeFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);

		clearFilterText();

		findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		typeFilterText("Zoolander");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNull("Found a node in the tree that should have been filtered out", node);
	}

	@Test
	public void testFilterFromSetFilterText() {
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		GTreeNode node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		setFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);

		clearFilterText();

		findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		setFilterText("Zoolander");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNull("Found a node in the tree that should have been filtered out", node);
	}

	@Test
	public void testRefilter() {
		final GTreeFilterProvider provider = new DefaultGTreeFilterProvider(gTree) {
			@Override
			public GTreeFilter getFilter() {
				if (filterEnabled) {
					return super.getFilter();
				}
				return new DisabledGTreeFilter();
			}
		};
		// Set the filter provider 
		runSwing(() -> gTree.setFilterProvider(provider));

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		//
		// Some basic filter tests
		//
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		GTreeNode node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		setFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);

		clearFilterText();

		findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		setFilterText("Zoolander");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNull("Found a node in the tree that should have been filtered out", node);

		//
		// Now try filtering and re-filtering
		//
		setFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);

		gTree.refilter();
		waitForTree();
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);

		filterEnabled = false;
		gTree.refilter();
		waitForTree();
		node = findNodeInTree("Leaf Child - Many B1");
		assertNull("Found node when filter should not have matched after a refilter", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);
	}

	@Test
	public void testChangeFilterSettingsWithFilterTextInPlace() {

		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		GTreeNode node2 = findNodeInTree("Leaf Child - Single B1");
		assertNotNull("Did not find existing child node in non filtered tree", node2);

		typeFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		setFilterOptions(TextFilterStrategy.CONTAINS, false);

		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		node2 = findNodeInTree("Leaf Child - Single B1");
		assertNull("Found a node in the tree that should have been filtered out", node2);
	}

	@Test
	public void testSelectionReturnsAfterFiltering() {
		//
		// Test that a selection made before a filter is still there after a filter
		//
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		gTree.setSelectedNode(node);
		waitForTree();

		TreePath selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		setFilterText("No match text");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNull("Found node that should have not passed filter", node);

		selectionPath = gTree.getSelectionPath();
		assertNull("Selection remained in tree after filter", selectionPath);

		clearFilterText();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		node = findNodeInTree("Leaf Child - Many B1");
		assertEquals(node, selectionPath.getLastPathComponent());
	}

	@Test
	public void testSelectionDuringFilterReturnsAfterFilter() {
		//
		// Test that a selection made during a filter returns after the filter is removed.
		//
		setFilterText("Many B1");
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		gTree.setSelectedNode(node);
		waitForTree();
		TreePath selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		clearFilterText();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		//
		// Same test, but with a selection that existed before the filter's selection change
		//
		gTree.clearSelectionPaths();
		waitForTree();

		gTree.setSelectedNode(node);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		setFilterText("ChildrenNodeA");// filter to show the node below

		GTreeNode anotherNode =
			findNodeInTree(NonLeafWithOneLevelOfChildrenNodeA.class.getSimpleName());
		assertNotNull("Could not find expected node", anotherNode);

		gTree.setSelectedNode(anotherNode);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(anotherNode, selectionPath.getLastPathComponent());

		clearFilterText();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(anotherNode, selectionPath.getLastPathComponent());
	}

	@Test
	public void testProgrammaticSelectAndFilter() {
		//
		// Open a node and select it.  Make sure it is again selected if it passes the filter.
		//
		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		gTree.setSelectedNode(node);
		waitForTree();

		TreePath selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		setFilterText("Many B1");
		node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in filtered tree", node);

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Node matching filter should still be selected after filter", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		clearFilterText();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		node = findNodeInTree("Leaf Child - Many B1");
		assertEquals(node, selectionPath.getLastPathComponent());
	}

	@Test
	public void testSetSelectedPaths() {
		TreePath selectionPath = gTree.getSelectionPath();
		assertNull("Unexpectedly have a selected path by default", selectionPath);

		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		gTree.setSelectedNode(node);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		gTree.clearSelectionPaths();
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNull("Selection paths not cleared", selectionPath);

		//
		// now try calling select node while another node is already selected
		//
		GTreeNode anotherNode =
			findNodeInTree(NonLeafWithOneLevelOfChildrenNodeA.class.getSimpleName());
		assertNotNull("Could not find expected node", anotherNode);

		gTree.setSelectedNode(node);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(node, selectionPath.getLastPathComponent());

		gTree.setSelectedNode(anotherNode);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(anotherNode, selectionPath.getLastPathComponent());

		// 
		// try multiple paths
		// 
		List<TreePath> pathsToSelect = new ArrayList<>();
		pathsToSelect.add(node.getTreePath());
		pathsToSelect.add(anotherNode.getTreePath());

		gTree.setSelectionPaths(pathsToSelect);
		waitForTree();

		TreePath[] paths = gTree.getSelectionPaths();
		assertEquals("Found non-matching selected path count afterr calling setSelectionPaths",
			pathsToSelect.size(), paths.length);
		for (int i = 0; i < paths.length; i++) {
			assertEquals("Unexpected path selection", pathsToSelect.get(i), paths[i]);
		}
	}

	@Test
	public void testExpandPath() {
		List<TreePath> expandedPaths = gTree.getExpandedPaths(gTree.getRootNode());
		assertEquals("Unexpectedly have an expanded tree by default", 1, expandedPaths.size());
		assertEquals(gTree.getRootNode(), expandedPaths.get(0).getLastPathComponent());

		GTreeNode node = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", node);

		gTree.expandPath(node);
		waitForTree();

		expandedPaths = gTree.getExpandedPaths(gTree.getRootNode());
		assertTrue("Did not get expanded paths after calling expand paths",
			expandedPaths.size() > 0);
		assertExpaned(expandedPaths, node.getParent());
	}

	@Test
	public void testPreventRootCollapseExpandsRoot() {
		gTree.collapseAll(gTree.getRootNode());
		waitForTree();

		gTree.setRootNodeAllowedToCollapse(false);
		waitForTree();

		List<TreePath> expanded = gTree.getExpandedPaths(gTree.getRootNode());

		assertEquals("Should have only one expanded path", 1, expanded.size());
		TreePath path0 = expanded.get(0);

		assertEquals(path0.getLastPathComponent(), gTree.getRootNode());
		assertEquals("Expanded path does not end at tree root", path0.getLastPathComponent(),
			gTree.getRootNode());
	}

	@Test
	public void testPreventRootCollapseAttemptsRootCollapse() {
		gTree.setRootNodeAllowedToCollapse(false);

		gTree.expandAll();
		waitForTree();

		gTree.collapseAll(gTree.getRootNode());
		waitForTree();

		List<TreePath> expanded = gTree.getExpandedPaths(gTree.getRootNode());

		assertEquals("Should have only one expanded path", 1, expanded.size());
		TreePath path0 = expanded.get(0);

		assertEquals("Expanded path does not end at tree root", path0.getLastPathComponent(),
			gTree.getRootNode());
	}

	@Test
	public void testCancelFilter() {
		//
		// Setup a long running filter and make sure that the progress bar is show.  Then, cancel
		// that filter and make sure that the filter is cleared and the progress bar is hidden.
		//

		final ReallySlowGTreeFilter filter = new ReallySlowGTreeFilter();
		final GTreeFilterProvider provider = new DefaultGTreeFilterProvider(gTree) {
			@Override
			public GTreeFilter getFilter() {
				GTreeFilter superFilter = super.getFilter();
				if (superFilter == null) {
					return null;
				}
				return filter;
			}
		};
		provider.setFilterText("Hey");
		// Set the filter  (Note: don't use setTextFilterFactory(), as it waits for the tree, 
		// which is not what this test wants to do)
		runSwing(() -> gTree.setFilterProvider(provider));

		// Wait for the tree to be 'busy'
		waitForTreeToStartWork();

		// Verify the progress monitor is showing
		assertProgressPanel(true);

		// Press the cancel button on the progress monitor
		pressProgressPanelCancelButton();

		waitForTree();

		// Verify no filter
		String filterText = gTree.getFilterText();
		assertEquals("", filterText);

		// Verify no progress component
		assertProgressPanel(false);
	}

	@Test
	public void testGetAndRestoreTreeState() {
		//
		// Test that we can setup the tree, record its state, change the tree and then restore
		// the saved state
		//
		TreePath selectionPath = gTree.getSelectionPath();
		assertNull("Unexpectedly have a selected path by default", selectionPath);

		GTreeNode originalNode = findNodeInTree("Leaf Child - Many B1");
		assertNotNull("Did not find existing child node in non filtered tree", originalNode);

		gTree.setSelectedNode(originalNode);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(originalNode, selectionPath.getLastPathComponent());

		GTreeState treeState = gTree.getTreeState();

		gTree.clearSelectionPaths();
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNull("Selection paths not cleared", selectionPath);

		GTreeNode anotherNode =
			findNodeInTree(NonLeafWithOneLevelOfChildrenNodeA.class.getSimpleName());
		assertNotNull("Could not find expected node", anotherNode);

		gTree.setSelectedNode(anotherNode);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(anotherNode, selectionPath.getLastPathComponent());

		gTree.restoreTreeState(treeState);
		waitForTree();

		selectionPath = gTree.getSelectionPath();
		assertNotNull("Tree did not select node", selectionPath);
		assertEquals(originalNode, selectionPath.getLastPathComponent());
	}

	@Test
	public void testFilterPathsRestoredWithFurtherFiltering_NoSelection() throws Exception {

		installLargeTreeModel();

		// this filter allows all children to stay in the view
		setFilterText("Leaf");

		TreePath firstVisiblePath = scrollTo(50);

		setFilterText("Leaf Child");

		TreePath newFirstVisiblePath = getLastVisiblePath();
		assertCloseEnough(firstVisiblePath, newFirstVisiblePath);
	}

	@Test
	public void testFilterPathsRestoredWithFurtherFiltering_HaveSelection() throws Exception {

		//
		// Test to verify that the selection restoration takes precedence over the 'visible 
		// view' restoration.
		//

		installLargeTreeModel();

		// this filter allows all children to stay in the view
		setFilterText("Leaf");

		selectRow(5);

		TreePath expected = getLastVisiblePath();

		scrollTo(50);

		setFilterText("Leaf Child");

		TreePath newFirstVisiblePath = getLastVisiblePath();
		assertCloseEnough(expected, newFirstVisiblePath);
	}

	@Test
	public void testFilterPathsRestored_WhenTooManyItemsExpanded_NoSelection() {

		//
		// Tests the algorithm for throwing away expanded paths when there are too many to
		// restore.
		//

		installLargeTreeModel_WithManyExpandablePaths();

		// generate more than 'max' expanded states to force the algorithm to toss some states
		expandAll();

		scrollTo(50);

		TreePath expected = getLastVisiblePath();

		// keep all items in filter; move the view to the top
		setFilterText("a");

		// verify that the view contains the expanded path
		TreePath newFirstVisiblePath = getLastVisiblePath();
		assertCloseEnough(expected, newFirstVisiblePath);
	}

	@Test
	public void testFilterPathsRestored_WhenTooManyItemsExpanded_HaveSelection() {

		//
		// Tests the algorithm for throwing away expanded paths when there are too many to
		// restore.
		//

		installLargeTreeModel_WithManyExpandablePaths();

		// generate more than 'max' expanded and selected states to force the algorithm 
		// to toss some states		
		expandAll();
		int topRow = 50;

		scrollTo(topRow);
		selectRow(topRow);

		// keep all items in filter; move the view to the top
		setFilterText("a");

		// verify that the view contains the selected path
		TreePath selectedPath = getSelectedPath();
		assertCloseEnough(rowToPath(topRow), selectedPath);
	}

	@Test
	public void testFilterPathsRestored_WhenTooManyItemsExpanded_HaveTooManyItemsSelected() {

		//
		// Tests the algorithm for throwing away expanded paths when there are too many to
		// restore.
		//

		installLargeTreeModel_WithManyExpandablePaths();

		// generate more than 'max' expanded and selected states to force the algorithm 
		// to toss some states		
		expandAll();
		int topRow = 50;

		scrollTo(topRow);
		selectContiguousRows(0, topRow + 5);

		// keep all items in filter; move the view to the top
		setFilterText("a");

		// verify that the view contains the selected path
		TreePath selectedPath = getSelectedPath();
		assertCloseEnough(rowToPath(topRow), selectedPath);
	}

//==================================================================================================
// Private methods
//==================================================================================================	

	private void installLargeTreeModel() {
		runSwing(() -> frame.getContentPane().remove(gTree));
		gTree = new TestGTree(new ManyLeafChildrenRootNode());
		runSwing(() -> frame.getContentPane().add(gTree));

		frame.validate();
	}

	private void installLargeTreeModel_WithManyExpandablePaths() {
		runSwing(() -> frame.getContentPane().remove(gTree));
		gTree = new TestGTree(new ManyNonLeafChildrenRootNode());
		runSwing(() -> frame.getContentPane().add(gTree));

		frame.validate();
	}

	private void expandAll() {
		gTree.expandAll();
		waitForTree();
	}

	private void selectRow(int row) {
		TreePath path = rowToPath(row);
		gTree.setSelectedNodeByPathName(path);
	}

	private void selectContiguousRows(int from, int to) {

		// hack: process the list backwards so that the 'to' row is what ends up in the view--the
		//       tree will scroll to the first selected element
		List<TreePath> paths = new ArrayList<>();
		for (int row = to; row >= from; row--) {
			paths.add(rowToPath(row));
		}

		gTree.setSelectionPaths(paths);
		waitForTree();
	}

	private TreePath rowToPath(int row) {
		TreePath path = gTree.getPathForRow(row);
		return path;
	}

	private void assertExpaned(List<TreePath> expandedPaths, GTreeNode expected) {

		for (TreePath path : expandedPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (expected.equals(node)) {
				return;
			}
		}

		fail("Node not expaded: " + expected + "; expanded paths: " + expandedPaths);
	}

	/** Verifies the actual is within one of the expected */
	private void assertCloseEnough(TreePath expected, TreePath actual) {

		if (actual == null) {
			fail("No actual TreePath found");
		}

		if (expected.equals(actual)) {
			return; // good
		}

		// Unusual Code: we add some 'fudge' to the viewable tree rows (1 in the top and 
		//               bottom direction).  So, the actual path visible may be off by that 
		//               much.
		int fudge = 2; // 1 in both directions
		int expectedRow = gTree.getRowForPath(expected);
		if (rowNumberIsWithin(expected, actual, fudge)) {
			return; // good enough
		}

		int actualRow = gTree.getRowForPath(actual);
		fail("Tree paths do not match - expected row " + expectedRow + "; actual row " + actualRow);
	}

	private boolean rowNumberIsWithin(TreePath expected, TreePath actual, int fudge) {

		//int expectedRow = gTree.getRowForPath(expected);
		int actualRow = gTree.getRowForPath(actual);

		// first, go up
		for (int offset = 0; offset > fudge; offset--) {
			int previousRow = actualRow - offset;
			TreePath previousPath = gTree.getPathForRow(previousRow);
			if (actual.equals(previousPath)) {
				return true; // good enough
			}
		}

		// next, go down
		for (int offset = 0; offset < fudge; offset++) {
			int previousRow = actualRow + offset;
			TreePath nextPath = gTree.getPathForRow(previousRow);
			if (actual.equals(nextPath)) {
				return true; // good enough
			}
		}

		return false;
	}

	private TreePath scrollTo(int row) {
		runSwing(() -> {
			TreePath path = gTree.getPathForRow(row);
			gTree.scrollPathToVisible(path);
		});

		TreePath path = getLastVisiblePath();
		return path;
	}

	private TreePath getLastVisiblePath() {
		Rectangle r = gTree.getViewRect();

		JTree jTree = gTree.getJTree();
		int start = jTree.getClosestRowForLocation(r.x, r.y + r.height);
		TreePath path = gTree.getPathForRow(start);
		return path;
	}

	@Override
	protected void testFailed(Throwable e) {
		StringBuilder buffy = new StringBuilder();
		printTree(gTree.getRootNode(), 0, buffy);
		System.err.println("GTree state: ");
		System.err.println(buffy.toString());
	}

	private void printTree(GTreeNode node, int indentLevel, StringBuilder buffy) {
		buffy.append('\n');
		for (int i = 0; i < indentLevel; i++) {
			buffy.append('\t');
		}
		buffy.append("node: " + node.getName());
		int nextIndentLevel = indentLevel + 1;
		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			printTree(child, nextIndentLevel, buffy);
		}
	}

	private void assertProgressPanel(boolean isShowing) {
		JComponent panel = (JComponent) getInstanceField("progressPanel", gTree);
		if (!isShowing) {
			assertNull("Panel is showing when it should not be", panel);
			return;
		}

		if (panel == null || !panel.isShowing()) {
			int maxWaits = 50;// wait a couple seconds, as the progress bar may be delayed
			int tryCount = 0;
			while (tryCount < maxWaits) {
				panel = (JComponent) getInstanceField("progressPanel", gTree);
				if (panel != null && panel.isShowing()) {
					return;// finally showing!
				}
				tryCount++;
				try {
					Thread.sleep(50);
				}
				catch (Exception e) {
					// who cares?
				}
			}
		}

		Assert.fail("Progress panel is not showing as expected");
	}

	private void pressProgressPanelCancelButton() {
		Object taskMonitorComponent = getInstanceField("monitor", gTree);
		final JButton cancelButton =
			(JButton) getInstanceField("cancelButton", taskMonitorComponent);
		runSwing(() -> cancelButton.doClick(), false);

		OptionDialog confirDialog = waitForDialogComponent(OptionDialog.class);
		JButton confirmCancelButton = findButtonByText(confirDialog, "Yes");
		runSwing(() -> confirmCancelButton.doClick());
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

	private void waitForTreeToStartWork() {

		waitForCondition(() -> gTree.isBusy(),
			"Tree did not start filtering task or finished too soon");
	}

	private void typeFilterText(String text) {
		Component filterField = gTree.getFilterField();
		JTextField textField = (JTextField) getInstanceField("textField", filterField);
		triggerText(textField, text);
		waitForTree();
	}

	private void setFilterText(final String text) {
		runSwing(() -> gTree.setFilterText(text));
		waitForTree();
	}

	private void clearFilterText() {
		setFilterText("");
	}

	private TreePath getSelectedPath() {
		waitForTree();
		return gTree.getSelectionPath();
	}

	private GTreeNode findNodeInTree(String name) {
		GTreeRootNode rootNode = gTree.getRootNode();
		return findNodeInTree(rootNode, name);
	}

	private GTreeNode findNodeInTree(GTreeNode node, String name) {
		if (node.getName().equals(name)) {
			return node;
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if (child.getName().startsWith(name)) {
				return child;
			}

			GTreeNode grandChild = findNodeInTree(child, name);
			if (grandChild != null) {
				return grandChild;
			}
		}

		return null;
	}

	private void setFilterOptions(final TextFilterStrategy filterStrategy, final boolean inverted) {
		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider()).setFilterOptions(
				filterOptions);
		});
		waitForTree();

	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestGTree extends GTree {

		public TestGTree(GTreeRootNode root) {
			super(root);
		}

		@Override
		public GTreeState getTreeState() {
			return new GTreeState(this) {
				@Override
				int getMaxItemCount() {
					return 5; // smaller number for testing
				}
			};
		}

		@Override
		public GTreeState getTreeState(GTreeNode node) {
			return new GTreeState(this, node) {
				@Override
				int getMaxItemCount() {
					return 5; // smaller number for testing
				}
			};
		}
	}

	private class TestRootNode extends AbstractGTreeRootNode {

		TestRootNode() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new NonLeafWithOneLevelOfChildrenNodeA());
			children.add(new LeafNode("Leaf Child - Root1"));
			children.add(new NonLeafWithManyLevelOfChildrenNodeA());
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Test GTree Root Node";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	private class ManyLeafChildrenRootNode extends AbstractGTreeRootNode {

		ManyLeafChildrenRootNode() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new NonLeafWithMoreChildrenThanFitInTheView(true));
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Test GTree Root Node";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	private class ManyNonLeafChildrenRootNode extends AbstractGTreeRootNode {

		ManyNonLeafChildrenRootNode() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new NonLeafWithMoreChildrenThanFitInTheView(false));
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Test GTree Root Node";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	/**
	 * A basic node with some children.
	 */
	private class NonLeafWithOneLevelOfChildrenNodeA extends AbstractGTreeNode {

		private String name = Integer.toString(++nodeIdCounter);

		NonLeafWithOneLevelOfChildrenNodeA() {
			List<GTreeNode> children = new ArrayList<>();
			setChildren(children);

		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName() + " (" + name + ")";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	/**
	 * A basic node with some children.
	 */
	private class NonLeafWithOneLevelOfChildrenNodeB extends AbstractGTreeNode {
		private String name = Integer.toString(++nodeIdCounter);

		NonLeafWithOneLevelOfChildrenNodeB() {
			this(1);
		}

		NonLeafWithOneLevelOfChildrenNodeB(int n) {
			List<GTreeNode> children = new ArrayList<>();
			name = Integer.toString(n);
			children.add(new LeafNode("Leaf Child - Single B" + n));
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName() + " (" + name + ")";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	/**
	 * A basic leaf node 
	 */
	private class LeafNode extends AbstractGTreeNode {

		private final String name;

		LeafNode(String name) {
			this.name = name;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}

	/**
	 * A node with children that may have children
	 */
	private class NonLeafWithManyLevelOfChildrenNodeA extends AbstractGTreeNode {

		private String name = Integer.toString(++nodeIdCounter);

		NonLeafWithManyLevelOfChildrenNodeA() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new NonLeafWithManyLevelOfChildrenNodeB());
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName() + " (" + name + ")";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	/**
	 * A node with children that may have children
	 */
	private class NonLeafWithManyLevelOfChildrenNodeB extends AbstractGTreeNode {

		private String name = Integer.toString(++nodeIdCounter);

		NonLeafWithManyLevelOfChildrenNodeB() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new NonLeafWithOneLevelOfChildrenNodeB());
			children.add(new LeafNode("Leaf Child - Many B1"));
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName() + " (" + name + ")";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	/**
	 * A basic node with some children.
	 */
	private class NonLeafWithMoreChildrenThanFitInTheView extends AbstractGTreeNode {

		private String name = Integer.toString(++nodeIdCounter);

		NonLeafWithMoreChildrenThanFitInTheView(boolean childrenAreLeaves) {
			List<GTreeNode> children = new ArrayList<>();

			for (int i = 0; i < 100; i++) {

				if (childrenAreLeaves) {
					children.add(new LeafNode("Leaf Child - " + i));
				}
				else {
					children.add(new NonLeafWithOneLevelOfChildrenNodeB(i));
				}

			}

			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName() + "(" + name + ")";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	private class DisabledGTreeFilter implements GTreeFilter {

		@Override
		public boolean acceptsNode(GTreeNode node) {
			return false;
		}

		@Override
		public boolean showFilterMatches() {
			return false;
		}

	}

	private class ReallySlowGTreeFilter implements GTreeFilter {

		@Override
		public boolean acceptsNode(GTreeNode node) {
			if (!SwingUtilities.isEventDispatchThread()) {
				// this filter is called by the worker thread AND the swing thread for rendering,
				// make sure not to wait in the swing thread
				sleep(2000);
			}
			return false;
		}

		@Override
		public boolean showFilterMatches() {
			return false;
		}

	}

}
