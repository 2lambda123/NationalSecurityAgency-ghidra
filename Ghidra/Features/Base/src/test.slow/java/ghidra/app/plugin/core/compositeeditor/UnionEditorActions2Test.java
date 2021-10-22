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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class UnionEditorActions2Test extends AbstractUnionEditorTest {

	@Test
	public void testCycleGroupOnComponent() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		getActions();
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 7);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertEquals(7, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new StringDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 10);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertEquals(10, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new UnicodeDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action);
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);
	}

}
