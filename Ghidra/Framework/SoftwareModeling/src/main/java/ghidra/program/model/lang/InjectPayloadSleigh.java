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
import java.util.List;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * <code>InjectPayloadSleigh</code> defines an InjectPayload of p-code which is defined via
 * a String passed to the sleigh compiler
 */
public class InjectPayloadSleigh implements InjectPayload {

	private ConstructTpl pcodeTemplate;
	private int paramShift;
	private boolean isfallthru;		// Precomputed fallthru of inject
	private boolean incidentalCopy;	// Treat COPY operations as incidental
	private InjectParameter[] inputlist;
	private InjectParameter[] output;
	private int subType;			// 0=uponentry 1=uponreturn
	protected String name;			// Formal name of this inject
	protected int type;				// type of this payload CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
	protected String source;			// Source of this payload
	private String parseString;		// String to be parsed for pcode

	/**
	 * Constructor for partial clone of another payload whose p-code failed to parse
	 * @param pcode is substitute p-code to replace the failed parse
	 * @param failedPayload is the failed payload
	 */
	protected InjectPayloadSleigh(ConstructTpl pcode, InjectPayloadSleigh failedPayload) {
		pcodeTemplate = pcode;
		paramShift = failedPayload.paramShift;
		incidentalCopy = failedPayload.incidentalCopy;
		inputlist = failedPayload.inputlist;
		output = failedPayload.output;
		subType = failedPayload.subType;
		name = failedPayload.name;
		type = failedPayload.type;
		source = failedPayload.source + "_FAILED";
		parseString = null;
		isfallthru = computeFallThru();
	}

	/**
	 * Constructor for a dummy payload, given just a name
	 * @param pcode is the dummy p-code sequence
	 * @param tp is the type of injection
	 * @param nm is the name of the injection
	 */
	protected InjectPayloadSleigh(ConstructTpl pcode, int tp, String nm) {
		pcodeTemplate = pcode;
		paramShift = 0;
		incidentalCopy = false;
		inputlist = new InjectParameter[0];
		output = new InjectParameter[0];
		subType = -1;
		name = nm;
		type = tp;
		source = "FAILED";
		parseString = null;
		isfallthru = computeFallThru();
	}

	/**
	 * Constructor for use where restoreXml is overridden and provides name and type
	 * @param sourceName is string describing the source of this payload
	 */
	protected InjectPayloadSleigh(String sourceName) {
		name = null;
		type = -1;
		subType = -1;
		incidentalCopy = false;
		inputlist = null;
		output = null;
		source = sourceName;
	}

	/**
	 * Provide basic form,  restoreXml fills in the rest
	 * @param nm  must provide formal name
	 * @param tp  must provide type
	 * @param sourceName is a description of the source of this payload
	 */
	public InjectPayloadSleigh(String nm, int tp, String sourceName) {
		name = nm;
		type = tp;
		subType = -1;
		inputlist = null;
		output = null;
		source = sourceName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return type;
	}

	@Override
	public String getSource() {
		return source;
	}

	@Override
	public int getParamShift() {
		return paramShift;
	}

	protected void setInputParameters(List<InjectParameter> in) {
		inputlist = new InjectParameter[in.size()];
		in.toArray(inputlist);
	}

	protected void setOutputParameters(List<InjectParameter> out) {
		output = new InjectParameter[out.size()];
		out.toArray(output);
	}

	@Override
	public InjectParameter[] getInput() {
		return inputlist;
	}

	@Override
	public InjectParameter[] getOutput() {
		return output;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) throws UnknownInstructionException,
			MemoryAccessException, IOException, NotFoundException {
		ParserWalker walker = emit.getWalker();
		walker.snippetState();
		setupParameters(context, walker);
		emit.build(pcodeTemplate, -1);
		emit.resolveRelatives();
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con)
			throws UnknownInstructionException, MemoryAccessException, IOException,
			NotFoundException {
		SleighParserContext protoContext =
			new SleighParserContext(con.baseAddr, con.nextAddr, con.refAddr, con.callAddr);
		ParserWalker walker = new ParserWalker(protoContext);
		PcodeEmitObjects emit = new PcodeEmitObjects(walker);
		inject(con, emit);
		return emit.getPcodeOp();
	}

	@Override
	public boolean isFallThru() {
		return isfallthru;
	}

	@Override
	public boolean isIncidentalCopy() {
		return incidentalCopy;
	}

	private boolean computeFallThru() {
		OpTpl[] opVec = pcodeTemplate.getOpVec();
		if (opVec.length <= 0) {
			return true;
		}
		switch (opVec[opVec.length - 1].getOpcode()) {
			case PcodeOp.BRANCH:
			case PcodeOp.BRANCHIND:
			case PcodeOp.RETURN:
				return false;
		}
		return true;
	}

	/**
	 *  All input and output parameters must have a unique index.
	 * Order them so that inputs come first, then outputs
	 */
	protected void orderParameters() {
		int id = 0;
		for (InjectParameter element : inputlist) {
			element.setIndex(id);
			id += 1;
		}
		for (InjectParameter element : output) {
			element.setIndex(id);
			id += 1;
		}
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_PCODE);
		if (type == CALLMECHANISM_TYPE && subType >= 0) {
			encoder.writeString(ATTRIB_INJECT, (subType == 0) ? "uponentry" : "uponreturn");
		}
		if (paramShift != 0) {
			encoder.writeSignedInteger(ATTRIB_PARAMSHIFT, paramShift);
		}
		if (pcodeTemplate == null) {
			encoder.writeBool(ATTRIB_DYNAMIC, true);
		}
		if (incidentalCopy) {
			encoder.writeBool(ATTRIB_INCIDENTALCOPY, incidentalCopy);
		}
		for (InjectParameter param : inputlist) {
			encoder.openElement(ELEM_INPUT);
			encoder.writeString(ATTRIB_NAME, param.getName());
			encoder.writeSignedInteger(ATTRIB_SIZE, param.getSize());
			encoder.closeElement(ELEM_INPUT);
		}
		for (InjectParameter param : output) {
			encoder.openElement(ELEM_OUTPUT);
			encoder.writeString(ATTRIB_NAME, param.getName());
			encoder.writeSignedInteger(ATTRIB_SIZE, param.getSize());
			encoder.closeElement(ELEM_OUTPUT);
		}
		if (pcodeTemplate != null) {
			// Decompiler will not read the <body> tag
			encoder.openElement(ELEM_BODY);
			encoder.writeString(ATTRIB_CONTENT, " local tmp:1 = 0; ");
			encoder.closeElement(ELEM_BODY);
		}
		encoder.closeElement(ELEM_PCODE);
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		ArrayList<InjectParameter> inlist = new ArrayList<>();
		ArrayList<InjectParameter> outlist = new ArrayList<>();
		XmlElement el = parser.start();			// The <pcode> tag
		String injectstr = el.getAttribute("inject");
		if (injectstr != null) {
			if (injectstr.equals("uponentry")) {
				subType = 0;
			}
			else if (injectstr.equals("uponreturn")) {
				subType = 1;
			}
			else {
				throw new XmlParseException("Unknown \"inject\" attribute value: " + injectstr);
			}
		}
		String pshiftstr = el.getAttribute("paramshift");
		paramShift = SpecXmlUtils.decodeInt(pshiftstr);
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		incidentalCopy = SpecXmlUtils.decodeBoolean(el.getAttribute("incidentalcopy"));
		XmlElement subel = parser.peek();
		while (subel.isStart()) {
			subel = parser.start();
			if (subel.getName().equals("body")) {
				parseString = parser.end(subel).getText();
				break;
			}
			String paramName = subel.getAttribute("name");
			int size = SpecXmlUtils.decodeInt(subel.getAttribute("size"));
			InjectParameter param = new InjectParameter(paramName, size);
			if (subel.getName().equals("input")) {
				inlist.add(param);
			}
			else {
				outlist.add(param);
			}
			parser.end(subel);
			subel = parser.peek();
		}
		parser.end(el);
		if (parseString != null) {
			parseString = parseString.trim();
			if (parseString.length() == 0) {
				parseString = null;
			}
		}
		if (parseString == null && (!isDynamic)) {
			throw new XmlParseException("Missing pcode <body> in injection: " + source);
		}

		setInputParameters(inlist);
		setOutputParameters(outlist);
		orderParameters();
	}

	String releaseParseString() {
		String res = parseString;
		parseString = null;			// Don't hold on to a reference
		return res;
	}

	protected void setTemplate(ConstructTpl ctl) {
		pcodeTemplate = ctl;
		isfallthru = computeFallThru();
	}

	/**
	 * Verify that the storage locations passed -con- match the restrictions for this payload
	 * @param con is InjectContext containing parameter storage locations
	 * @throws NotFoundException for expected aspects of the context that are not present
	 */
	private void checkParameterRestrictions(InjectContext con, Address addr)
			throws NotFoundException {
		int insize = (con.inputlist == null) ? 0 : con.inputlist.size();
		if (inputlist.length != insize) {
			throw new NotFoundException(
				"Input parameters do not match specification " + name + " in\n" + source);
		}
		for (int i = 0; i < inputlist.length; ++i) {
			int sz = inputlist[i].getSize();
			if (sz != 0 && sz != con.inputlist.get(i).getSize()) {
				throw new NotFoundException(
					"Input parameter size does not match specification " + name + " in\n" + source);
			}
		}
		int outsize = (con.output == null) ? 0 : con.output.size();
		if (output.length != outsize) {
			if (outsize == 0) {
				throw new NotFoundException(
					"Output expected by specification " + name + " in\n" + source);
			}
			throw new NotFoundException(
				"Output not expected by specification " + name + " in\n" + source);
		}
		for (int i = 0; i < output.length; ++i) {
			int sz = output[i].getSize();
			if (sz != 0 && sz != con.output.get(i).getSize()) {
				throw new NotFoundException(
					"Output size does not match specification " + name + " in\n" + source);
			}
		}
	}

	/**
	 * Set-up operands in the parser state so that they pick up storage locations from InjectContext
	 * @param con is the InjectContext containing storage locations
	 * @param walker is the sleigh parser state object
	 * @throws UnknownInstructionException if there are too many parameters for the parser
	 * @throws NotFoundException for expected aspects of the context that are not present
	 */
	private void setupParameters(InjectContext con, ParserWalker walker)
			throws UnknownInstructionException, NotFoundException {
		checkParameterRestrictions(con, walker.getAddr());
		for (int i = 0; i < inputlist.length; ++i) {
			walker.allocateOperand();
			Varnode vn = con.inputlist.get(i);
			FixedHandle hand = walker.getParentHandle();
			hand.space = vn.getAddress().getAddressSpace();
			hand.offset_offset = vn.getOffset();
			hand.size = vn.getSize();
			hand.offset_space = null;
			walker.popOperand();
		}
		for (int i = 0; i < output.length; ++i) {
			walker.allocateOperand();
			Varnode vn = con.output.get(i);
			FixedHandle hand = walker.getParentHandle();
			hand.space = vn.getAddress().getAddressSpace();
			hand.offset_offset = vn.getOffset();
			hand.size = vn.getSize();
			hand.offset_space = null;
			walker.popOperand();
		}
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadSleigh op2 = (InjectPayloadSleigh) obj;
		if (!name.equals(op2.name)) {
			return false;
		}
		if (inputlist.length != op2.inputlist.length) {
			return false;
		}
		for (int i = 0; i < inputlist.length; ++i) {
			if (!inputlist[i].isEquivalent(op2.inputlist[i])) {
				return false;
			}
		}
		if (output.length != op2.output.length) {
			return false;
		}
		for (int i = 0; i < output.length; ++i) {
			if (!output[i].isEquivalent(op2.output[i])) {
				return false;
			}
		}
		if (incidentalCopy != op2.incidentalCopy) {
			return false;
		}
		// Cannot compare isfallthru as it is a product of the p-code templates
//		if (isfallthru != op2.isfallthru) {
//			return false;
//		}
		if (paramShift != op2.paramShift) {
			return false;
		}
		if (type != op2.type || subType != op2.subType) {
			return false;
		}
		// We are NOT checking parseString and pcodeTemplate
		return true;
	}

	/**
	 * Build a dummy p-code sequence to use in place of a normal parsed payload.
	 * A ConstructTpl is built out of Varnode and PcodeOp templates that can
	 * be assigned directly to the pcodeTemplate field of the payload.
	 * The sequence itself is non-empty, consisting of a single operation:
	 *    tmp = tmp + 0;
	 * @param addrFactory is used to construct temp and constant Varnodes
	 * @return the final dummy template
	 */
	public static ConstructTpl getDummyPcode(AddressFactory addrFactory) {
		ConstTpl uniqueSpace = new ConstTpl(addrFactory.getUniqueSpace());
		ConstTpl constSpace = new ConstTpl(addrFactory.getConstantSpace());
		ConstTpl tmpOffset = new ConstTpl(ConstTpl.REAL, 0x100);
		ConstTpl constZero = new ConstTpl(ConstTpl.REAL, 0);
		ConstTpl size = new ConstTpl(ConstTpl.REAL, 4);
		VarnodeTpl temp = new VarnodeTpl(uniqueSpace, tmpOffset, size);
		VarnodeTpl zero = new VarnodeTpl(constSpace, constZero, size);
		VarnodeTpl[] inputs = new VarnodeTpl[2];
		inputs[0] = temp;
		inputs[1] = zero;
		OpTpl[] ops = new OpTpl[1];
		ops[0] = new OpTpl(PcodeOp.INT_ADD, temp, inputs);
		ConstructTpl pcode = new ConstructTpl(ops);
		return pcode;
	}
}
