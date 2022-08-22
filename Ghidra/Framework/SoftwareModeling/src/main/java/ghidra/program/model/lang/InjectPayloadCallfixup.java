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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

public class InjectPayloadCallfixup extends InjectPayloadSleigh {

	protected List<String> targetSymbolNames;

	/**
	 * Constructor for a partial clone of a payload whose p-code failed to parse.
	 * @param pcode is the p-code to substitute
	 * @param failedPayload is the failed callfixup
	 */
	protected InjectPayloadCallfixup(ConstructTpl pcode, InjectPayloadCallfixup failedPayload) {
		super(pcode, failedPayload);
		targetSymbolNames = failedPayload.targetSymbolNames;
	}

	/**
	 * Construct a dummy payload
	 * @param pcode is the dummy p-code sequence to use
	 * @param nm is the name of the payload
	 */
	protected InjectPayloadCallfixup(ConstructTpl pcode, String nm) {
		super(pcode, CALLFIXUP_TYPE, nm);
		targetSymbolNames = new ArrayList<>();
	}

	public InjectPayloadCallfixup(String sourceName) {
		super(sourceName);
		type = CALLFIXUP_TYPE;
		targetSymbolNames = new ArrayList<>();
	}

	public List<String> getTargets() {
		return targetSymbolNames;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CALLFIXUP);
		encoder.writeString(ATTRIB_NAME, name);
		for (String nm : targetSymbolNames) {
			encoder.openElement(ELEM_TARGET);
			encoder.writeString(ATTRIB_NAME, nm);
			encoder.closeElement(ELEM_TARGET);
		}
		super.encode(encoder);
		encoder.closeElement(ELEM_CALLFIXUP);
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement fixupEl = parser.start("callfixup");
		name = fixupEl.getAttribute("name");
		boolean pcodeSubtag = false;
		while (parser.peek().isStart()) {
			String elname = parser.peek().getName();
			if (elname.equals("target")) {
				XmlElement subel = parser.start();
				String targetName = subel.getAttribute("name");
				if (targetName == null) {
					throw new XmlParseException("Invalid callfixup target, missing target name");
				}
				targetSymbolNames.add(targetName);
				parser.end(subel);
			}
			else if (elname.equals("pcode")) {
				super.restoreXml(parser, language);
				pcodeSubtag = true;
			}
			else {
				throw new XmlParseException("Unknown callfixup tag: " + elname);
			}
		}
		if (!pcodeSubtag) {
			throw new XmlParseException("<callfixup> missing <pcode> subtag: " + name);
		}
		parser.end(fixupEl);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadCallfixup op2 = (InjectPayloadCallfixup) obj;
		if (!targetSymbolNames.equals(op2.targetSymbolNames)) {
			return false;
		}
		return super.isEquivalent(obj);
	}
}
