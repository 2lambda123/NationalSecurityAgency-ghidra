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
package ghidra.program.model.pcode;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Local variables visible to a function.  This includes mapped (on the stack) and
 * unmapped (only stored in a register).
 * 
 */
public class LocalSymbolMap {
	private HighFunction func;				// Function to which these variables are local
	private String spacename;
	private HashMap<MappedVarKey, HighSymbol> addrMappedSymbols;	// Hashed by addr and pcaddr
	private HashMap<Integer, HighSymbol> symbolMap;  			// Hashed by unique key
	private MappedSymbol[] paramSymbols;

	/**
	 * @param highFunc HighFunction the local variables are defined within.
	 * @param spcname space name the local variables are defined within.
	 */
	public LocalSymbolMap(HighFunction highFunc, String spcname) {
		func = highFunc;
		spacename = spcname;
		addrMappedSymbols = new HashMap<MappedVarKey, HighSymbol>();
		symbolMap = new HashMap<Integer, HighSymbol>();
		paramSymbols = new MappedSymbol[0];
	}

	public HighFunction getHighFunction() {
		return func;
	}

	/**
	 * Populate the local variable map from information attached to the Program DB's function.
	 * @param includeDefaultNames is true if default symbol names should be considered locked
	 */
	public void grabFromFunction(boolean includeDefaultNames) {
		Function dbFunction = func.getFunction();
		int uniqueSymbolId = 0;
		Variable locals[] = dbFunction.getLocalVariables();
		for (Variable local : locals) {
			Variable var = local;
			if (!var.isValid()) {
				// exclude locals which don't have valid storage
				continue;
			}
			DataType dt = var.getDataType();
			boolean istypelock = true;
			boolean isnamelock = true;
			if (Undefined.isUndefined(dt)) {
				istypelock = false;
			}
			int sz = var.getLength();
			String name = var.getName();

			VariableStorage storage = var.getVariableStorage();
			Address defAddr = null;
			if (!storage.isStackStorage()) {
				defAddr = dbFunction.getEntryPoint().addWrap(var.getFirstUseOffset());
			}
			HighSymbol sym;
			if (storage.isHashStorage()) {
				sym =
					newDynamicSymbol(name, dt, sz, storage.getFirstVarnode().getOffset(), defAddr,
						0, ++uniqueSymbolId);
			}
			else {
				sym = newMappedSymbol(name, dt, storage, defAddr, -1, ++uniqueSymbolId);
			}
			sym.setTypeLock(istypelock);
			sym.setNameLock(isnamelock);
		}

		Parameter[] p = dbFunction.getParameters();
		boolean lock = (dbFunction.getSignatureSource() != SourceType.DEFAULT);

		Address pcaddr = dbFunction.getEntryPoint();
		try {
			pcaddr = pcaddr.subtract(1);
		}
		catch (AddressOutOfBoundsException e) {
			// Should rarely happen
		}

		List<MappedSymbol> paramList = new ArrayList<MappedSymbol>();
		for (int i = 0; i < p.length; ++i) {
			Parameter var = p[i];
			if (!var.isValid()) {
				// TODO: exclude parameters which don't have valid storage ??
				continue;
			}
			DataType dt = var.getDataType();
			String name = var.getName();
			VariableStorage storage = var.getVariableStorage();
			Address resAddr = storage.isStackStorage() ? null : pcaddr;
			MappedSymbol paramSymbol =
				newMappedSymbol(name, dt, storage, resAddr, i, ++uniqueSymbolId);
			paramList.add(paramSymbol);
			boolean namelock = true;
			if (!includeDefaultNames) {
				namelock = isUserDefinedName(name);
			}
			paramSymbol.setNameLock(namelock);
			paramSymbol.setTypeLock(lock);
		}

		paramSymbols = new MappedSymbol[paramList.size()];
		paramList.toArray(paramSymbols);
		Arrays.sort(paramSymbols, PARAM_SYMBOL_SLOT_COMPARATOR);

		uniqueSymbolId = grabEquates(dbFunction, uniqueSymbolId);
	}

	private boolean isUserDefinedName(String name) {
		if (name.startsWith("local_")) {
			return false;
		}
		if (name.startsWith("param_")) {
			return false;
		}
		return true;
	}

	/**
	 * Parse a &lt;mapsym&gt; tag in XML
	 * @param parser is the XML parser
	 * @return the reconstructed HighSymbol
	 * @throws PcodeXMLException for problems sub tags
	 */
	private HighSymbol parseSymbolXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement node = parser.start("mapsym");
		String typename = node.getAttribute("type");
		HighSymbol res = null;
		if (typename == null) {
			res = new MappedSymbol();
		}
		else if (typename.equals("dynamic")) {
			res = new DynamicSymbol();
		}
		else if (typename.equals("equate")) {
			res = new EquateSymbol();
		}

		int symbolId = res.restoreXML(parser, func);
		parser.end(node);
		insertSymbol(res,symbolId);
		return res;
	}

	/**
	 * Parse a local symbol scope in XML from the &lt;localdb&gt; tag.
	 * 
	 * @param parser is the XML parser
	 * @throws PcodeXMLException for problems parsing individual tags
	 */
	public void parseScopeXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("localdb");
		spacename = el.getAttribute("main");
		XmlElement scopeel = parser.start("scope");

		parser.discardSubTree();	// This is the parent scope path
		parser.discardSubTree();	// This is the address range

		addrMappedSymbols.clear();			// Clear out any old map
		symbolMap.clear();			// Clear out any old map

		XmlElement nextEl = parser.peek();
		if (nextEl != null && nextEl.isStart() && "symbollist".equals(nextEl.getName())) {
			parseSymbolList(parser);
		}
		parser.end(scopeel);
		parser.end(el);
	}

	private static final Comparator<MappedSymbol> PARAM_SYMBOL_SLOT_COMPARATOR =
		new Comparator<MappedSymbol>() {
			@Override
			public int compare(MappedSymbol sym1, MappedSymbol sym2) {
				return sym1.getSlot() - sym2.getSlot();
			}
		};

	/**
	 * Add mapped symbols to this LocalVariableMap, by parsing the &lt;symbollist&gt; and &lt;mapsym&gt; tags.
	 * @param parser is the XML parser
	 * @throws PcodeXMLException for problems parsing a tag
	 */
	public void parseSymbolList(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("symbollist");
		ArrayList<MappedSymbol> parms = new ArrayList<MappedSymbol>();
		while (parser.peek().isStart()) {
			HighSymbol sym = parseSymbolXML(parser);
			if (sym instanceof MappedSymbol && ((MappedSymbol) sym).isParameter()) {
				parms.add((MappedSymbol) sym);
			}
		}
		paramSymbols = new MappedSymbol[parms.size()];
		parms.toArray(paramSymbols);
		Arrays.sort(paramSymbols, PARAM_SYMBOL_SLOT_COMPARATOR);
		parser.end(el);
	}

	/**
	 * @return an XML document string representing this local variable map.
	 */
	public String buildLocalDbXML() {		// Get memory mapped local variables
		StringBuilder res = new StringBuilder();
		res.append("<localdb");
		SpecXmlUtils.encodeBooleanAttribute(res, "lock", false);
		SpecXmlUtils.encodeStringAttribute(res, "main", spacename);
		res.append(">\n");
		res.append("<scope");
		SpecXmlUtils.xmlEscapeAttribute(res, "name", func.getFunction().getName());
		res.append(">\n");
		res.append("<parent>\n");
		HighFunction.createNamespaceTag(res, func.getFunction().getParentNamespace());
		res.append("</parent>\n");
		res.append("<rangelist/>\n");	// Empty address range
		res.append("<symbollist>\n");
		Iterator<HighSymbol> iter = symbolMap.values().iterator();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			res.append(sym.buildXML());
		}
		res.append("</symbollist>\n");
		res.append("</scope>\n");
		res.append("</localdb>\n");
		return res.toString();
	}

	/**
	 * Get all the symbols mapped for this program, Param, Locals.
	 * The HighSymbol can either be a HighParam, or HighLocal
	 * 
	 * @return an iterator over all mapped symbols.
	 */
	public Iterator<HighSymbol> getSymbols() {
		return symbolMap.values().iterator();
	}

	/**
	 * Find any local variable (including input params) by address
	 * @param store - variable storage
	 * @param pc = Address of first use, or null if address
	 *             is valid throughout the entire scope
	 * @return HighLocal or null
	 */
	public HighSymbol findLocal(VariableStorage store, Address pc) {
		MappedVarKey key = new MappedVarKey(store, pc);
		return addrMappedSymbols.get(key);
	}

	/**
	 * Find any local variable (including input params) by address
	 * @param addr - variable storage address
	 * @param pc = Address of first use, or null if address
	 *             is valid throughout the entire scope
	 * @return HighLocal or null
	 */
	public HighSymbol findLocal(Address addr, Address pc) {
		MappedVarKey key = new MappedVarKey(addr, pc);
		return addrMappedSymbols.get(key);
	}

	/**
	 * Lookup high variable based upon its symbol-id
	 * @param id symbol-id
	 * @return variable or null if not found
	 */
	public HighSymbol getSymbol(int id) {
		return symbolMap.get(id);
	}

	public int getNumParams() {
		return paramSymbols.length;
	}

	public MappedSymbol getParamSymbol(int i) {
		return paramSymbols[i];
	}

	public HighParam getParam(int i) {
		return (HighParam) paramSymbols[i].getHighVariable();
	}

	public boolean containsVariableWithName(String name) {
		Collection<HighSymbol> values = symbolMap.values();
		for (HighSymbol sym : values) {
			if (sym.getName().equals(name)) {
				return true;
			}
		}
		return false;
	}

	public MappedSymbol newMappedSymbol(String nm, DataType dt, VariableStorage store,
			Address pcaddr, int slot, int id) {
		MappedSymbol sym = new MappedSymbol(nm, dt, store, pcaddr, func, slot);
		insertSymbol(sym,id);
		return sym;
	}

	public DynamicSymbol newDynamicSymbol(String nm, DataType dt, int sz, long hash,
			Address pcaddr, int format, int id) {
		DynamicSymbol sym = new DynamicSymbol(nm, dt, sz, func, pcaddr, hash, format);
		insertSymbol(sym,id);
		return sym;
	}

	private void insertSymbol(HighSymbol sym,int id) {
		if (sym instanceof MappedSymbol) {
			MappedSymbol mapSym = (MappedSymbol)sym;
			MappedVarKey key = new MappedVarKey(mapSym.getStorage(),mapSym.getPCAddress());
			addrMappedSymbols.put(key, sym);
		}
		symbolMap.put(id, sym);
	}

	private void newEquateSymbol(String nm, long val, long hash, Address addr, int format,
			TreeMap<String, DynamicSymbol> constantSymbolMap) {
		DynamicSymbol eqSymbol = constantSymbolMap.get(nm);
		if (eqSymbol != null) {
			eqSymbol.addReference(addr, hash, format);	// New reference to same symbol
			return;
		}
		int conv = EquateSymbol.convertName(nm, val);
		if (conv < 0) {
			eqSymbol = new EquateSymbol(nm, val, func, addr, hash, format);
			eqSymbol.setNameLock(true);
		}
		else {
			eqSymbol = new EquateSymbol(conv, val, func, addr, hash, format);
		}
		//Do NOT setTypeLock
		constantSymbolMap.put(nm, eqSymbol);
	}

	/**
	 * Build dynamic symbols based on equates
	 * @param dbFunction is the function to pull equates for
	 * @param uniqueSymbolId is the next available symbol id
	 * @return the next available symbol id
	 */
	private int grabEquates(Function dbFunction, int uniqueSymbolId) {
		TreeMap<String, DynamicSymbol> constantSymbolMap = null;
		// Find named constants via Equates
		Program program = dbFunction.getProgram();
		EquateTable equateTable = program.getEquateTable();
		Listing listing = program.getListing();
		AddressIterator equateAddresses = equateTable.getEquateAddresses(dbFunction.getBody());
		while (equateAddresses.hasNext()) {
			Address defAddr = equateAddresses.next();
			for (Equate eq : equateTable.getEquates(defAddr)) {
				Instruction instr = listing.getInstructionAt(defAddr);
				if (instr == null) {
					continue;
				}
				long hash[] = DynamicHash.calcConstantHash(instr, eq.getValue());
				for (long element : hash) {
					if (constantSymbolMap == null) {
						constantSymbolMap = new TreeMap<String, DynamicSymbol>();
					}
					newEquateSymbol(eq.getDisplayName(), eq.getValue(), element, defAddr, 0,
						constantSymbolMap);
				}
			}
		}

// TODO: Find typed constants via DataTypeReferences
//		-- for each datatype reference within the scope of the function
//		MappedVarKey key = new MappedVarKey(AddressSpace.HASH_SPACE.getAddress(hash),defAddr);
//		DynamicSymbol sym = constantSymbolMap.get(key);
//		String name = sym != null ? sym.getName() : null;
//		sym = new DynamicSymbol(name, dt, dt.getLength(), hash, defAddr, func, 0); // format??
//		if (name != null) {
//			sym.setTypeLock(true);
//		}
//		sym.setTypeLock(true);
//		sym.setReadOnly(true);
//		

// Add constant dynamic symbols to map
		if (constantSymbolMap != null) {
			for (DynamicSymbol sym : constantSymbolMap.values()) {
				symbolMap.put(++uniqueSymbolId, sym);
			}
		}
		return uniqueSymbolId;
	}

	/**
	 * Hashing keys for Local variables
	 * 
	 *
	 */
	class MappedVarKey {
		private Address addr;
		private Address pcaddr;

		public MappedVarKey(Address addr, Address pcad) {
			this.addr = addr;
			if (!addr.isStackAddress()) {
				// first use not supported for stack
				pcaddr = pcad;
			}
		}

		public MappedVarKey(VariableStorage store, Address pcad) {
			addr = store.getFirstVarnode().getAddress();
			if (!addr.isStackAddress()) {
				// first use not supported for stack
				pcaddr = pcad;
			}
		}

		@Override
		public boolean equals(Object op2) {
			MappedVarKey op = (MappedVarKey) op2;
			if (!SystemUtilities.isEqual(pcaddr, op.pcaddr)) {
				return false;
			}
			return addr.equals(op.addr);
		}

		@Override
		public int hashCode() {
			int hash1 = addr.hashCode();
			int hash2 = pcaddr != null ? pcaddr.hashCode() : 0;
			return (hash1 << 4) ^ hash2;
		}
	}

}
