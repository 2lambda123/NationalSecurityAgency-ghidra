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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import org.junit.*;

import docking.*;
import docking.test.AbstractDockingTest;
import docking.widgets.filter.*;
import ghidra.test.DummyTool;
import ghidra.util.StringUtilities;

public class GTreeFilterTest extends AbstractDockingTest {

	private GTree gTree;
	private FilterTextField filterField;

	private GTreeRootNode root;

	private DockingWindowManager winMgr;

	@Before
	public void setUp() throws Exception {
		root = new TestRootNode();
		gTree = new GTree(root);

		filterField = (FilterTextField) gTree.getFilterField();

		winMgr = new DockingWindowManager(new DummyTool(), null);
		winMgr.addComponent(new TestTreeComponentProvider());
		winMgr.setVisible(true);

		waitForTree();
	}

	@After
	public void tearDown() throws Exception {
		winMgr.dispose();
	}

	@Test
	public void testContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		assertEquals("Expected 4 of nodes to be in filtered tree!", 4, root.getChildCount());

		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

		setFilterText("MMM");
		assertEquals("Expected 4 of nodes to be in filtered tree!", 0, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ',
			MultitermEvaluationMode.AND);

		setFilterText("CX AB");
		assertEquals(2, root.getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ', MultitermEvaluationMode.OR);

		setFilterText("CX AB");
		assertEquals(4, root.getChildCount());

		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testMultiWordContainsDelimiters() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			setFilterText("CX" + delim + "AB");
			assertEquals(2, root.getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delim + "AB");
			assertEquals(4, root.getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
		}

	}

	@Test
	public void testMultiWordContainsDelimitersWithLeadingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delimPad + delim;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, root.getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, root.getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());

		}
	}

	@Test
	public void testMultiWordContainsDelimitersWithTrailingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delim + delimPad;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, root.getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, root.getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());

		}
	}

	@Test
	public void testMultiWordContainsDelimitersWithBoundingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delimPad + delim + delimPad;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, root.getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, root.getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());

		}
	}

	@Test
	public void testInvertedContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true);

		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		assertEquals(1, root.getChildCount());

		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("XABC");
		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");

		setFilterText("MMM");
		assertEquals(5, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testInvertedMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.AND);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("CX AB");

		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(3, root.getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.OR);
		setFilterText("");
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("CX AB");

		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(1, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, root.getChildCount());

		setFilterText("MMM");
		assertEquals(0, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testInvertedStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("ABCX");
		assertEquals(3, root.getChildCount());

		setFilterText("MMM");
		assertEquals(5, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		assertEquals(1, root.getChildCount());

		setFilterText("MMM");
		assertEquals(0, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testInvertedExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		assertEquals(4, root.getChildCount());

		setFilterText("MMM");
		assertEquals(5, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testRegExMatch() {
		setFilterOptions(TextFilterStrategy.REGULAR_EXPRESSION, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("^ABC$");
		checkContainsNode("ABC");
		assertEquals("Expected 1 node match exacly match ABC!", 1, root.getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");
		assertEquals("Expected 4 of nodes that contain the text ABC!", 4, root.getChildCount());

		setFilterText("XA.{0,2}X");
		checkContainsNode("XABCX");
		assertEquals(1, root.getChildCount());

		setFilterText("X{0,1}A.{0,2}X");
		checkContainsNode("XABCX");
		checkContainsNode("ABCX");
		assertEquals(2, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testInvertedRegExMatch() {
		setFilterOptions(TextFilterStrategy.REGULAR_EXPRESSION, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, root.getChildCount());

		setFilterText("^ABC$");
		checkDoesNotContainsNode("ABC");
		assertEquals(4, root.getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("XABC");
		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(1, root.getChildCount());

		setFilterText("XA.{0,2}X");
		checkDoesNotContainsNode("XABCX");
		assertEquals(4, root.getChildCount());

		setFilterText("X{0,1}A.{0,2}X");
		checkDoesNotContainsNode("XABCX");
		checkDoesNotContainsNode("ABCX");
		assertEquals(3, root.getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, root.getChildCount());
	}

	@Test
	public void testSwitchFilterTypes() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, root.getChildCount());

		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		checkContainsNode("ABC");
		assertEquals(1, root.getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		assertEquals("Expected 4 of nodes to be in filtered tree!", 4, root.getChildCount());
		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

	}

	@Test
	public void testSavingSelectedFilterType() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		setFilterText("ABC");
		checkContainsNode("ABC");
		assertEquals(1, root.getChildCount());

		Object originalValue = getInstanceField("uniquePreferenceKey", gTree);
		setInstanceField("preferenceKey", gTree.getFilterProvider(), "XYZ");
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, root.getChildCount());

		setInstanceField("preferenceKey", gTree.getFilterProvider(), originalValue);
		setInstanceField("optionsSet", gTree.getFilterProvider(), false);
		restorePreferences();
		checkContainsNode("ABC");
		assertEquals(1, root.getChildCount());

	}

	private void restorePreferences() {
		runSwing(() -> {
			GTreeFilterProvider filterProvider = gTree.getFilterProvider();
			String key = (String) getInstanceField("uniquePreferenceKey", gTree);
			Class<?>[] classes = new Class[] { DockingWindowManager.class, String.class };
			Object[] objs = new Object[] { winMgr, key };
			invokeInstanceMethod("loadFilterPreference", filterProvider, classes, objs);
		});
		waitForTree();
	}

	private void checkContainsNode(String string) {
		List<GTreeNode> children = root.getChildren();
		for (GTreeNode gTreeNode : children) {
			if (gTreeNode.getName().equals(string)) {
				return;
			}
		}
		Assert.fail("Expected node " + string + " to be included in filter, but was not found!");
	}

	private void checkDoesNotContainsNode(String string) {
		List<GTreeNode> children = root.getChildren();
		for (GTreeNode gTreeNode : children) {
			if (gTreeNode.getName().equals(string)) {
				Assert.fail("Expected node " + string +
					" to be NOT be included in filter, but was not found!");
			}
		}
	}

	private void setFilterText(final String text) {
		runSwing(() -> {
			filterField.setText(text);
		});
		waitForTree();
	}

	private void setFilterOptions(final TextFilterStrategy filterStrategy, final boolean inverted) {

		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider()).setFilterOptions(
				filterOptions);
		});
		waitForTree();

	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean inverted,
			boolean multiTerm, char splitCharacter, MultitermEvaluationMode evalMode) {
		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted,
				multiTerm, splitCharacter, evalMode);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider()).setFilterOptions(
				filterOptions);
		});
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

	private class TestRootNode extends AbstractGTreeRootNode {

		TestRootNode() {
			List<GTreeNode> children = new ArrayList<>();
			children.add(new LeafNode("XYZ"));
			children.add(new LeafNode("ABC"));
			children.add(new LeafNode("ABCX"));
			children.add(new LeafNode("XABC"));
			children.add(new LeafNode("XABCX"));
			setChildren(children);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Root";
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

	class TestTreeComponentProvider extends ComponentProvider {

		public TestTreeComponentProvider() {
			super(null, "Test", "Test");
			setDefaultWindowPosition(WindowPosition.STACK);
			setTabText("Test");
		}

		@Override
		public JComponent getComponent() {
			return gTree;
		}

		@Override
		public String getTitle() {
			return "Test Tree";
		}
	}

}
