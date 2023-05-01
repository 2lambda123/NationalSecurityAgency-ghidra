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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.VarnodeData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Standard analysis for parameter lists
 *
 */
public class ParamListStandard implements ParamList {

	protected int numgroup;			// Number of "groups" in this parameter convention
//	protected int maxdelay;
	protected int pointermax;		// If non-zero, maximum size of a datatype before converting to a pointer
	protected boolean thisbeforeret;	// Do hidden return pointers usurp the storage of the this pointer
	protected boolean splitMetatype;	// Are metatyped entries in separate resource sections
//	protected int[] resourceStart;		// The starting group for each resource section
	protected ParamEntry[] entry;
	protected AddressSpace spacebase;	// Space containing relative offset parameters

	/**
	 * Find the (first) entry containing range
	 * @param loc  is base address of the range
	 * @param size is the size of the range in bytes
	 * @return the index of entry or -1 if we didn't find container
	 */
	private int findEntry(Address loc, int size) {
		for (int i = 0; i < entry.length; ++i) {
			if (entry[i].getMinSize() > size) {
				continue;
			}
			if (entry[i].justifiedContain(loc, size) == 0) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Assign next available memory chunk to type
	 * @param program is the Program
	 * @param tp type being assigned storage
	 * @param status  status from previous assignments
	 * @param ishiddenret is true if the parameter is a hidden return value
	 * @param isindirect is true if parameter is really a pointer to the real parameter value
	 * @return Address of assigned memory chunk
	 */
	protected VariableStorage assignAddress(Program program, DataType tp, int[] status,
			boolean ishiddenret, boolean isindirect) {
		if (tp == null) {
			tp = DataType.DEFAULT;
		}
		if (VoidDataType.isVoidDataType(tp)) {
			return VariableStorage.VOID_STORAGE;
		}
		int sz = tp.getLength();
		if (sz == 0) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		for (ParamEntry element : entry) {
			int grp = element.getGroup();
			if (status[grp] < 0) {
				continue;
			}
			if ((element.getType() != ParamEntry.TYPE_UNKNOWN) &&
				(ParamEntry.getMetatype(tp) != element.getType())) {
				continue;		// Wrong type
			}

			VarnodeData res = new VarnodeData();
			status[grp] = element.getAddrBySlot(status[grp], tp.getLength(), res);
			if (res.space == null) {
				continue;	// -tp- does not fit in this entry
			}
			if (element.isExclusion()) {
				for (int group : element.getAllGroups()) {
					// For an exclusion entry
					status[group] = -1;			// some number of groups are taken up
				}
				if (element.isFloatExtended()) {
					sz = element.getSize();			// Still use the entire container size, when assigning storage
				}
			}
			VariableStorage store;
			try {
				if (res.space.getType() == AddressSpace.TYPE_JOIN) {
					Varnode[] pieces = element.getJoinPieces(sz);
					if (pieces != null) {
						store = new DynamicVariableStorage(program, false, pieces);
					}
					else {
						store = DynamicVariableStorage.getUnassignedDynamicStorage(false);
					}
				}
				else {
					Address addr = res.space.getAddress(res.offset);
					if (ishiddenret) {
						store = new DynamicVariableStorage(program,
							AutoParameterType.RETURN_STORAGE_PTR, addr, sz);
					}
					else if (isindirect) {
						store = new DynamicVariableStorage(program, true, addr, sz);
					}
					else {
						store = new DynamicVariableStorage(program, false, addr, sz);
					}
				}
			}
			catch (InvalidInputException e) {
				break;
			}
			return store;
		}
		if (ishiddenret) {
			return DynamicVariableStorage
					.getUnassignedDynamicStorage(AutoParameterType.RETURN_STORAGE_PTR);
		}
		return DynamicVariableStorage.getUnassignedDynamicStorage(isindirect);
	}

	@Override
	public void assignMap(Program prog, DataType[] proto, ArrayList<VariableStorage> res,
			boolean addAutoParams) {
		int[] status = new int[numgroup];
		for (int i = 0; i < numgroup; ++i) {
			status[i] = 0;
		}

		if (addAutoParams && res.size() == 2) {	// Check for hidden parameters defined by the output list
			DataTypeManager dtm = prog.getDataTypeManager();
			Pointer pointer = dtm.getPointer(proto[0]);
			VariableStorage store = assignAddress(prog, pointer, status, true, false);
			res.set(1, store);
		}
		for (int i = 1; i < proto.length; ++i) {
			VariableStorage store;
			if ((pointermax != 0) && (proto[i] != null) && (proto[i].getLength() > pointermax)) {	// DataType is too big
				// Assume datatype is stored elsewhere and only the pointer is passed
				DataTypeManager dtm = prog.getDataTypeManager();
				Pointer pointer = dtm.getPointer(proto[i]);
				store = assignAddress(prog, pointer, status, false, true);
			}
			else {
				store = assignAddress(prog, proto[i], status, false, false);
			}
			res.add(store);
		}
	}

	@Override
	public VariableStorage[] getPotentialRegisterStorage(Program prog) {
		ArrayList<VariableStorage> res = new ArrayList<>();
		for (ParamEntry element : entry) {
			ParamEntry pe = element;
			if (!pe.isExclusion()) {
				continue;
			}
			if (pe.getSpace().isRegisterSpace()) {
				VariableStorage var = null;
				try {
					var = new VariableStorage(prog, pe.getSpace().getAddress(pe.getAddressBase()),
						pe.getSize());
				}
				catch (InvalidInputException e) {
					// Skip this particular storage location
				}
				if (var != null) {
					res.add(var);
				}
			}
		}
		VariableStorage[] arres = new VariableStorage[res.size()];
		res.toArray(arres);
		return arres;
	}

	@Override
	public void encode(Encoder encoder, boolean isInput) throws IOException {
		encoder.openElement(isInput ? ELEM_INPUT : ELEM_OUTPUT);
		if (pointermax != 0) {
			encoder.writeSignedInteger(ATTRIB_POINTERMAX, pointermax);
		}
		if (thisbeforeret) {
			encoder.writeBool(ATTRIB_THISBEFORERETPOINTER, true);
		}
		if (isInput && !splitMetatype) {
			encoder.writeBool(ATTRIB_SEPARATEFLOAT, false);
		}
		int curgroup = -1;
		for (ParamEntry el : entry) {
			if (curgroup >= 0) {
				if (!el.isGrouped() || el.getGroup() != curgroup) {
					encoder.closeElement(ELEM_GROUP);
					curgroup = -1;
				}
			}
			if (el.isGrouped()) {
				if (curgroup < 0) {
					encoder.openElement(ELEM_GROUP);
					curgroup = el.getGroup();
				}
			}
			el.encode(encoder);
		}
		if (curgroup >= 0) {
			encoder.closeElement(ELEM_GROUP);
		}
		encoder.closeElement(isInput ? ELEM_INPUT : ELEM_OUTPUT);
	}

	private void parsePentry(XmlPullParser parser, CompilerSpec cspec, ArrayList<ParamEntry> pe,
			int groupid, boolean splitFloat, boolean grouped) throws XmlParseException {
		int lastMeta = -1;		// Smaller than any real metatype
		if (!pe.isEmpty()) {
			ParamEntry lastEntry = pe.get(pe.size() - 1);
			lastMeta = lastEntry.isGrouped() ? ParamEntry.TYPE_UNKNOWN : lastEntry.getType();
		}
		ParamEntry pentry = new ParamEntry(groupid);
		pe.add(pentry);
		pentry.restoreXml(parser, cspec, pe, grouped);
		if (splitFloat) {
			int currentMeta = grouped ? ParamEntry.TYPE_UNKNOWN : pentry.getType();
			if (lastMeta != currentMeta) {
				if (lastMeta > currentMeta) {
					throw new XmlParseException(
						"parameter list entries must be ordered by metatype");
				}
//				int[] newResourceStart = new int[resourceStart.length + 1];
//				System.arraycopy(resourceStart, 0, newResourceStart, 0, resourceStart.length);
//				newResourceStart[resourceStart.length] = groupid;
//				resourceStart = newResourceStart;
			}
		}
		if (pentry.getSpace().isStackSpace()) {
			spacebase = pentry.getSpace();
		}
		int[] groupSet = pentry.getAllGroups();
		int maxgroup = groupSet[groupSet.length - 1] + 1;
		if (maxgroup > numgroup) {
			numgroup = maxgroup;
		}
	}

	private void parseGroup(XmlPullParser parser, CompilerSpec cspec, ArrayList<ParamEntry> pe,
			int groupid, boolean splitFloat) throws XmlParseException {
		XmlElement el = parser.start("group");
		int basegroup = numgroup;
		int count = 0;
		while (parser.peek().isStart()) {
			parsePentry(parser, cspec, pe, basegroup, splitFloat, true);
			count += 1;
			ParamEntry lastEntry = pe.get(pe.size() - 1);
			if (lastEntry.getSpace().getType() == AddressSpace.TYPE_JOIN) {
				throw new XmlParseException(
					"<pentry> in the join space not allowed in <group> tag");
			}
		}
		// Check that all entries in the group are distinguishable
		for (int i = 1; i < count; ++i) {
			ParamEntry curEntry = pe.get(pe.size() - 1 - i);
			for (int j = 0; j < i; ++j) {
				ParamEntry.orderWithinGroup(curEntry, pe.get(pe.size() - 1 - j));
			}
		}
		parser.end(el);
	}

	@Override
	public void restoreXml(XmlPullParser parser, CompilerSpec cspec) throws XmlParseException {
		ArrayList<ParamEntry> pe = new ArrayList<>();
		numgroup = 0;
		spacebase = null;
		pointermax = 0;
		thisbeforeret = false;
		splitMetatype = true;
		XmlElement mainel = parser.start();
		String attribute = mainel.getAttribute("pointermax");
		if (attribute != null) {
			pointermax = SpecXmlUtils.decodeInt(attribute);
		}
		attribute = mainel.getAttribute("thisbeforeretpointer");
		if (attribute != null) {
			thisbeforeret = SpecXmlUtils.decodeBoolean(attribute);
		}
		attribute = mainel.getAttribute("separatefloat");
		if (attribute != null) {
			splitMetatype = SpecXmlUtils.decodeBoolean(attribute);
		}
//		resourceStart = new int[0];
		for (;;) {
			XmlElement el = parser.peek();
			if (!el.isStart()) {
				break;
			}
			if (el.getName().equals("pentry")) {
				parsePentry(parser, cspec, pe, numgroup, splitMetatype, false);
			}
			else if (el.getName().equals("group")) {
				parseGroup(parser, cspec, pe, numgroup, splitMetatype);
			}
		}
		parser.end(mainel);
		entry = new ParamEntry[pe.size()];
		pe.toArray(entry);
//		int[] newResourceStart = new int[resourceStart.length + 1];
//		System.arraycopy(resourceStart, 0, newResourceStart, 0, resourceStart.length);
//		newResourceStart[resourceStart.length] = numgroup;
//		resourceStart = newResourceStart;
	}

	@Override
	public int getStackParameterAlignment() {
		for (ParamEntry pentry : entry) {
			if (pentry.getSpace().isStackSpace()) {
				return pentry.getAlign();
			}
		}
		return -1;
	}

	@Override
	public Long getStackParameterOffset() {
		for (ParamEntry element : entry) {
			ParamEntry pentry = element;
			if (pentry.isExclusion()) {
				continue;
			}
			if (!pentry.getSpace().isStackSpace()) {
				continue;
			}
			long res = pentry.getAddressBase();
			if (pentry.isReverseStack()) {
				res += pentry.getSize();
			}
			res = pentry.getSpace().truncateOffset(res);
			return res;
		}
		return null;
	}

	@Override
	public boolean possibleParamWithSlot(Address loc, int size, WithSlotRec res) {
		if (loc == null) {
			return false;
		}
		int num = findEntry(loc, size);
		if (num == -1) {
			return false;
		}
		ParamEntry curentry = entry[num];
		res.slot = curentry.getSlot(loc, 0);
		if (curentry.isExclusion()) {
			res.slotsize = curentry.getAllGroups().length;
		}
		else {
			res.slotsize = ((size - 1) / curentry.getAlign()) + 1;
		}
		return true;
	}

	@Override
	public boolean isEquivalent(ParamList obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		ParamListStandard op2 = (ParamListStandard) obj;
		if (entry.length != op2.entry.length) {
			return false;
		}
		for (int i = 0; i < entry.length; ++i) {
			if (!entry[i].isEquivalent(op2.entry[i])) {
				return false;
			}
		}
		if (numgroup != op2.numgroup || pointermax != op2.pointermax) {
			return false;
		}
		if (!SystemUtilities.isEqual(spacebase, op2.spacebase)) {
			return false;
		}
		if (thisbeforeret != op2.thisbeforeret) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isThisBeforeRetPointer() {
		return thisbeforeret;
	}
}
