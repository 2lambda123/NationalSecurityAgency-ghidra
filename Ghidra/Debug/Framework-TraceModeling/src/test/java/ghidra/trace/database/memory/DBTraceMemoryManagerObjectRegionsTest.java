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
package ghidra.trace.database.memory;

import org.junit.Before;

import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.util.database.UndoableTransaction;

public class DBTraceMemoryManagerObjectRegionsTest extends DBTraceMemoryManagerRegionsTest {

	protected SchemaContext ctx;

	@Before
	public void setUpObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Regions' schema='RegionContainer' />" + //
			"    </schema>" + //
			"    <schema name='RegionContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Region' />" + //
			"    </schema>" + //
			"    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='MemoryRegion' />" + //
			"    </schema>" + //
			"</context>");

		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}
}
