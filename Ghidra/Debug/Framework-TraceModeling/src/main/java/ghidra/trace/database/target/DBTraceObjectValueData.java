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
package ghidra.trace.database.target;

import java.io.IOException;
import java.util.Objects;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBCachedObjectStoreFactory.*;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.DBTreeDataRecord;

@DBAnnotatedObjectInfo(version = 1)
public class DBTraceObjectValueData
		extends DBTreeDataRecord<ValueShape, ValueBox, DBTraceObjectValueData>
		implements TraceObjectValueStorage, ValueShape {
	static final String TABLE_NAME = "ObjectValue";

	static final String PARENT_COLUMN_NAME = "Parent"; // R*-Tree parent
	static final String OBJ_PARENT_COLUMN_NAME = "ObjParent"; // Object-Tree parent
	static final String ENTRY_KEY_COLUMN_NAME = "EntryKey";
	static final String MIN_SNAP_COLUMN_NAME = "MinSnap";
	static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";
	static final String CHILD_COLUMN_NAME = "Child";
	static final String PRIMITIVE_COLUMN_NAME = "Primitive";

	@DBAnnotatedColumn(PARENT_COLUMN_NAME)
	static DBObjectColumn PARENT_COLUMN;
	@DBAnnotatedColumn(OBJ_PARENT_COLUMN_NAME)
	static DBObjectColumn OBJ_PARENT_COLUMN;
	@DBAnnotatedColumn(ENTRY_KEY_COLUMN_NAME)
	static DBObjectColumn ENTRY_KEY_COLUMN;
	@DBAnnotatedColumn(MIN_SNAP_COLUMN_NAME)
	static DBObjectColumn MIN_SNAP_COLUMN;
	@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
	static DBObjectColumn MAX_SNAP_COLUMN;
	@DBAnnotatedColumn(CHILD_COLUMN_NAME)
	static DBObjectColumn CHILD_COLUMN;
	@DBAnnotatedColumn(PRIMITIVE_COLUMN_NAME)
	static DBObjectColumn PRIMITIVE_COLUMN;

	@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
	private long parentKey;
	@DBAnnotatedField(column = OBJ_PARENT_COLUMN_NAME, codec = DBTraceObjectDBFieldCodec.class)
	private DBTraceObject objParent;
	@DBAnnotatedField(column = ENTRY_KEY_COLUMN_NAME)
	private String entryKey;
	@DBAnnotatedField(column = MIN_SNAP_COLUMN_NAME)
	private long minSnap;
	@DBAnnotatedField(column = MAX_SNAP_COLUMN_NAME)
	private long maxSnap;
	@DBAnnotatedField(
		column = CHILD_COLUMN_NAME,
		indexed = true,
		codec = DBTraceObjectDBFieldCodec.class)
	private DBTraceObject child;
	@DBAnnotatedField(column = PRIMITIVE_COLUMN_NAME, codec = VariantDBFieldCodec.class)
	private Object primitive;

	protected final DBTraceObjectManager manager;
	protected final DBTraceObjectValueRStarTree tree;

	protected ValueBox bounds;
	protected Lifespan lifespan;
	protected Address address;
	protected AddressRange range;

	private DBTraceObjectValue wrapper;

	public DBTraceObjectValueData(DBTraceObjectManager manager, DBTraceObjectValueRStarTree tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(store, record);
		this.manager = manager;
		this.tree = tree;
	}

	void doSetPrimitive(Object primitive) {
		if (primitive instanceof TraceObject) {
			throw new AssertionError();
		}
		else if (primitive instanceof Address address) {
			this.address = address;
			this.range = null;
			this.primitive = RecAddress.fromAddress(address);
		}
		else if (primitive instanceof AddressRange range) {
			this.address = null;
			this.range = range;
			this.primitive = RecRange.fromRange(range);
		}
		else {
			this.address = null;
			this.range = null;
			this.primitive = primitive;
		}
		update(PRIMITIVE_COLUMN);
	}

	protected long getObjParentKey() {
		return objParent == null ? -1 : objParent.getKey();
	}

	protected long getObjChildKey() {
		return child == null ? -1 : child.getKey();
	}

	@Override
	public int getAddressSpaceId() {
		if (primitive instanceof RecAddress addr) {
			return addr.spaceId();
		}
		if (primitive instanceof RecRange rng) {
			return rng.spaceId();
		}
		return -1;
	}

	@Override
	public long getMinAddressOffset() {
		if (primitive instanceof RecAddress addr) {
			return addr.offset();
		}
		if (primitive instanceof RecRange rng) {
			return rng.min();
		}
		return 0;
	}

	@Override
	public long getMaxAddressOffset() {
		if (primitive instanceof RecAddress addr) {
			return addr.offset();
		}
		if (primitive instanceof RecRange rng) {
			return rng.max();
		}
		return 0;
	}

	protected void updateBounds() {
		long objParentKey = getObjParentKey();
		long objChildKey = getObjChildKey();
		int spaceId = getAddressSpaceId();
		bounds = new ImmutableValueBox(
			new ValueTriple(objParentKey, objChildKey, entryKey, minSnap,
				new RecAddress(spaceId, getMinAddressOffset())),
			new ValueTriple(objParentKey, objChildKey, entryKey, maxSnap,
				new RecAddress(spaceId, getMaxAddressOffset())));
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		updateBounds();
		lifespan = Lifespan.span(minSnap, maxSnap);
		if (primitive instanceof RecAddress address) {
			this.address = address.toAddress(manager.trace.getBaseAddressFactory());
			this.range = null;
		}
		else if (primitive instanceof RecRange range) {
			this.address = null;
			this.range = range.toRange(manager.trace.getBaseAddressFactory());
		}
		else {
			this.address = null;
			this.range = null;
		}
	}

	@Override
	public DBTraceObject getParent() {
		return objParent;
	}

	@Override
	public String getEntryKey() {
		return entryKey;
	}

	@Override
	public Object getValue() {
		if (child != null) {
			return child;
		}
		if (address != null) {
			return address;
		}
		if (range != null) {
			return range;
		}
		return child != null ? child : primitive;
	}

	@Override
	public DBTraceObject getChild() {
		return (DBTraceObject) getValue();
	}

	@Override
	public Lifespan getLifespan() {
		return lifespan;
	}

	@Override
	protected boolean shapeEquals(ValueShape shape) {
		if (objParent != shape.getParent()) {
			return false;
		}
		if (!Objects.equals(entryKey, shape.getEntryKey())) {
			return false;
		}
		if (!Objects.equals(lifespan, shape.getLifespan())) {
			return false;
		}
		return true;
	}

	@Override
	protected void setRecordValue(DBTraceObjectValueData value) {
		// Nothing. Entry is the value
	}

	@Override
	protected DBTraceObjectValueData getRecordValue() {
		return this;
	}

	@Override
	public ValueShape getShape() {
		return this;
	}

	@Override
	public ValueBox getBounds() {
		return bounds;
	}

	@Override
	public void setShape(ValueShape shape) {
		objParent = shape.getParent();
		child = shape.getChild();
		entryKey = shape.getEntryKey();
		minSnap = shape.getLifespan().lmin();
		maxSnap = shape.getLifespan().lmax();
		// Space/Address/Range will be set by doSetPrimitive 
		update(OBJ_PARENT_COLUMN, CHILD_COLUMN, ENTRY_KEY_COLUMN, MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);

		lifespan = shape.getLifespan();
		bounds = shape.getBounds();
	}

	@Override
	public long getParentKey() {
		return parentKey;
	}

	@Override
	public void setParentKey(long parentKey) {
		this.parentKey = parentKey;
		update(PARENT_COLUMN);
	}

	@Override
	public String description() {
		return new ImmutableValueShape(getShape()).toString();
	}

	@Override
	public DBTraceObjectManager getManager() {
		return manager;
	}

	@Override
	public DBTraceObject getChildOrNull() {
		return child;
	}

	@Override
	public void doSetLifespan(Lifespan lifespan) {
		// NB. Wrapper would not call if lifespan weren't different
		DBTraceObjectValueRStarTree tree = this.tree;
		tree.doUnparentEntry(this);
		minSnap = lifespan.lmin();
		maxSnap = lifespan.lmax();
		update(MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);
		this.lifespan = lifespan;
		updateBounds();
		tree.doInsertDataEntry(this);
	}

	@Override
	public void doDelete() {
		manager.doDeleteValue(this);
	}

	@Override
	public DBTraceObjectValue getWrapper() {
		if (wrapper == null) {
			wrapper = new DBTraceObjectValue(manager, this);
		}
		return wrapper;
	}

	void setWrapper(DBTraceObjectValue wrapper) {
		if (this.wrapper != null) {
			throw new AssertionError();
		}
		this.wrapper = wrapper;
	}
}
