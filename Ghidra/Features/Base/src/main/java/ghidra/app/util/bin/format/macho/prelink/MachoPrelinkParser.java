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
package ghidra.app.util.bin.format.macho.prelink;

import java.io.*;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.util.NumericUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public class MachoPrelinkParser {

	private static final String TAG_DATA = "data";
	private static final String TAG_FALSE = "false";
	private static final String TAG_TRUE = "true";
	private static final String TAG_INTEGER = "integer";
	private static final String TAG_STRING = "string";
	private static final String TAG_KEY = "key";
	private static final String TAG_DICT = "dict";
	private static final String TAG_ARRAY = "array";

	private Map<String, String> idToStrings = new HashMap<String, String>();
	private Map<String, Long> idToIntegers = new HashMap<String, Long>();

	private MachHeader mainHeader;
	private ByteProvider provider;

	public MachoPrelinkParser(MachHeader mainHeader, ByteProvider provider) {
		this.mainHeader = mainHeader;
		this.provider = provider;
	}

	public List<MachoPrelinkMap> parse(TaskMonitor monitor)
			throws IOException, JDOMException, NoPreLinkSectionException {
		InputStream inputStream = findPrelinkInputStream();

		monitor.setMessage("Parsing prelink plist...");

		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Document doc = sax.build(inputStream);
		Element root = doc.getRootElement();

		List<MachoPrelinkMap> list = new ArrayList<MachoPrelinkMap>();

		if (root.getName().equals(TAG_ARRAY)) { // iOS version before 4.x
			process(root.getChildren(), list, monitor);
		}
		else {
			Iterator<?> iterator = root.getChildren().iterator();
			while (iterator.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}
				Element element = (Element) iterator.next();
				if (element.getName().equals(TAG_DICT)) {
					// top level is <dict> entry
					processTopDict(monitor, list, element);
				}
				else if (element.getName().equals(TAG_KEY)) {
					processKey(monitor, list, iterator, element);
				}
			}
		}

		return list;
	}
	
	private void processTopDict(TaskMonitor monitor, List<MachoPrelinkMap> list,
		Element dictRootElement) {
		Iterator<?> iterator = dictRootElement.getChildren().iterator();
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Element element = (Element) iterator.next();
			if (element.getName().equals(TAG_KEY)) {
				processKey(monitor, list, iterator, element);
			}
		}
	}

	private void processKey(TaskMonitor monitor, List<MachoPrelinkMap> list, Iterator<?> iterator,
			Element element) {
		String value = element.getValue();
		if (value.equals(MachoPrelinkConstants.kPrelinkPersonalitiesKey)) {
			Element arrayElement = (Element) iterator.next();
			if (arrayElement.getChildren().size() == 0) {
				//should be empty...
			}
		}
		else if (value.equals(MachoPrelinkConstants.kPrelinkInfoDictionaryKey)) {
			Element arrayElement = (Element) iterator.next();
			process(arrayElement.getChildren(), list, monitor);
		}
	}

	private void process(List<?> children, List<MachoPrelinkMap> list, TaskMonitor monitor) {
		monitor.setMessage("Processing prelink information...");

		for (int i = 0; i < children.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			Element element = (Element) children.get(i);
			if (element.getName().equals(TAG_DICT)) {
				MachoPrelinkMap map = processElement(element, monitor);
				list.add(map);
			}
		}
	}

	private MachoPrelinkMap processElement(Element parentElement, TaskMonitor monitor) {
		MachoPrelinkMap map = new MachoPrelinkMap();
		Iterator<?> iterator = parentElement.getChildren().iterator();
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Element element = (Element) iterator.next();
			if (element.getName().equals(TAG_KEY)) {
				Element valueElement = (Element) iterator.next();
				processValue(element, valueElement, map, monitor);
			}
			else {
				//TODO bad parse state...
			}
		}
		return map;
	}

	private String processValue(Element keyElement, Element valueElement, MachoPrelinkMap map,
			TaskMonitor monitor) {
		String key = keyElement.getValue();
		if (valueElement.getName().equals(TAG_STRING)) {
			return processString(map, key, valueElement);
		}
		else if (valueElement.getName().equals(TAG_INTEGER)) {
			return processInteger(map, key, valueElement);
		}
		else if (valueElement.getName().equals(TAG_TRUE)) {
			map.put(key, true);
			return "true";
		}
		else if (valueElement.getName().equals(TAG_FALSE)) {
			map.put(key, false);
			return "false";
		}
		else if (valueElement.getName().equals(TAG_DATA)) {
			map.put(key, valueElement.getValue());
			return valueElement.getValue();
		}
		else if (valueElement.getName().equals(TAG_DICT)) {
			MachoPrelinkMap dictMap = processElement(valueElement, monitor);
			map.put(key, dictMap);
			return dictMap.toString();
		}
		else if (valueElement.getName().equals(TAG_ARRAY)) {
			String arrayString = processArray(valueElement, map, monitor);
			map.put(key, arrayString);
			return arrayString;
		}
		else {
			System.out.println("Unhandled value type: " + valueElement.getName());
			return valueElement.getValue();
		}
	}

	private String processString(MachoPrelinkMap map, String key, Element valueElement) {
		String value = valueElement.getValue();
		String id = valueElement.getAttributeValue("ID");
		String idref = valueElement.getAttributeValue("IDREF");

		if (id != null) {
			idToStrings.put(id, value);
		}
		if (value != null) {
			map.put(key, valueElement.getValue());
		}
		if (idref != null) {
			map.put(key, idToStrings.get(idref));
		}
		return value;
	}

	private String processInteger(MachoPrelinkMap map, String key, Element valueElement) {
		String value = valueElement.getValue();
		String id = valueElement.getAttributeValue("ID");
		String idref = valueElement.getAttributeValue("IDREF");

		long numericValue = -1;
		try {
			numericValue = NumericUtilities.parseHexLong(value);
		}
		catch (Exception e) {
			// do nothing
		}

		if (id != null) {
			idToIntegers.put(id, numericValue);
		}

		map.put(key, numericValue);

		if (idref != null) {
			map.put(key, idToIntegers.get(idref));
		}

		return value;
	}

	private String processArray(Element arrayElement, MachoPrelinkMap map, TaskMonitor monitor) {
		if (!arrayElement.getName().equals(TAG_ARRAY)) {
			throw new RuntimeException("not an array element");
		}
		StringBuffer buffer = new StringBuffer();
		Iterator<?> iterator = arrayElement.getChildren().iterator();
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Element arrayChildElement = (Element) iterator.next();
			processElement(arrayChildElement, monitor);

			String value = processValue(arrayElement, arrayChildElement, map, monitor);

			buffer.append(value);

			if (iterator.hasNext()) {
				buffer.append(',');
			}
		}
		return buffer.toString();
	}

	private InputStream findPrelinkInputStream() throws IOException, NoPreLinkSectionException {
		InputStream prelinkInputStream = null;
		List<SegmentCommand> segments = mainHeader.getLoadCommands(SegmentCommand.class);
		for (SegmentCommand segment : segments) {
			if (segment.getSegmentName().equals(MachoPrelinkConstants.kPrelinkSegment_iOS_1x) ||
				segment.getSegmentName().equals(MachoPrelinkConstants.kPrelinkInfoSegment)) {
				Section section = segment.getSectionByName(MachoPrelinkConstants.kPrelinkInfoSection);
				if (section != null && section.getSize() > 0) {
					byte[] bytes = provider.readBytes(section.getOffset(), section.getSize() - 1);

					String string = new String(bytes);

					String trimmed = string.trim();

					if (trimmed.endsWith("</>Apple")) {//this is a wank-around the malformed XML found in 3.0 firmwares
						trimmed = trimmed.substring(0, trimmed.length() - 8) + "</array>";
					}
					if (trimmed.endsWith("</4.2</shoneOS<")) {//this is a wank-around the malformed XML found in 4.2.x firmwares
						trimmed = trimmed.substring(0, trimmed.length() - 15) + "</array></dict>";
					}
					
					int doctypeIndex = trimmed.indexOf("<!DOCTYPE");
					if (doctypeIndex >=0) {
						int endOfDoctype = trimmed.indexOf('>', doctypeIndex);
						if (endOfDoctype >=0) {
							trimmed = trimmed.substring(0,doctypeIndex) + trimmed.substring(endOfDoctype+1);
						}
					}
					// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

					//fix bytes so XML will parse...

					prelinkInputStream = new ByteArrayInputStream(trimmed.getBytes());
				}
			}
		}
		if (prelinkInputStream == null) {
			throw new NoPreLinkSectionException(
				"Unable to locate __info section in __PRELINK segment inside mach-o header for COMPLZSS file system.");
		}
		return prelinkInputStream;
	}
}
