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
package ghidra.util.datastruct;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class IntLongIndexedListTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public IntLongIndexedListTest() {
		super();
	}

@Test
    public void testIntLongIndexedList() {

        IntLongIndexedList ilist = new IntLongIndexedList(7);

        System.out.println("Test add to list 0");
        ilist.add(0,20l);
        ilist.add(0,10l);
        ilist.add(0,0l);
        expect(ilist,0, new long[] {0l,10l,20l}, "Add: ");

        System.out.println("Test append");
        ilist.append(6,30l);
        ilist.append(6,40l);
        ilist.append(6,50l);
        expect(ilist,0, new long[] {0l,10l,20l}, "Add: ");
        expect(ilist, 6, new long[] {30l,40l,50l}, "Append");


        System.out.println("Test contains");
        if (!ilist.contains(0,0l)) {
            Assert.fail("list 0 does not contain 0, but it should");
        }
        if (!ilist.contains(0,10l)) {
            Assert.fail("list 0 does not contain 10, but it should");
        }
        if (!ilist.contains(0,20l)) {
            Assert.fail("list 0 does not contain 20, but it should");
        }
        if (ilist.contains(0,30l)) {
            Assert.fail("list 0 contains 30, but it should not");
        }
        if (ilist.contains(1,50l)) {
            Assert.fail("list 1 contains 50, but it should not");
        }
        if (!ilist.contains(6,50l)) {
            Assert.fail("list 6 does not contain 50, but it should");
        }

        System.out.println("Test remove");
        ilist.remove(0,0l);
        ilist.remove(6,50l);
        expect(ilist,0, new long[] {10l,20l}, "Remove ");
        expect(ilist, 6, new long[] {30l,40l}, "Remove ");

        System.out.println("Test removeAll");
        ilist.removeAll(0);
        expect(ilist,0,new long[]{},"RemoveAll ");
        expect(ilist,1,new long[]{},"RemoveAll ");
        expect(ilist,6,new long[]{30,40},"RemoveAll ");



        System.out.println("Test add after removeAll");
        ilist.add(0,100l);
        ilist.add(0,200l);
        ilist.add(0,300l);
        expect(ilist,0,new long[]{300l,200l,100l}, "Add after removeAll");

        ilist.removeAll(0);
        ilist.removeAll(6);
        System.out.println("Test growing the number of lists");
        for(int i=0;i<ilist.getNumLists();i++) {
            for(long j=0;j<10;j++) {
                ilist.append(i,j);
            }
        }

        ilist.growNumLists(13);
        for(int i=0;i<13;i++) {
            if (i < 7) {
                expect(ilist,i,new long[]{0,1,2,3,4,5,6,7,8,9}, "Grow lists ");
            }
            else {
                expect(ilist,i,new long[]{},"Grow Lists ");
            }
        }
    }// end doTest()

    public static void expect(IntLongIndexedList ilist, int listId, long[] values, String test) {

        long[] listValues = ilist.get(listId);
        if (values.length != listValues.length) {
            Assert.fail(test + " expected list "+listId+ "to be of length "+
                    values.length + ", but instead it was of length "+listValues.length);
        }
        for(int i=0;i<listValues.length;i++) {
            if (listValues[i] != values[i]) {
                Assert.fail(test + "list["+listId+"], item "+i+
                    "should contain "+values[i]+", but instead contains "+listValues[i]);
            }
        }
    }
}
