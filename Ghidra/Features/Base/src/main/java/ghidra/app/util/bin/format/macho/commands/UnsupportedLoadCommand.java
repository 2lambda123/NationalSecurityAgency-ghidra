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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class UnsupportedLoadCommand extends LoadCommand {
	private int type;

	static UnsupportedLoadCommand createUnsupportedLoadCommand(
			FactoryBundledWithBinaryReader reader, int type) throws IOException {
		UnsupportedLoadCommand command =
			(UnsupportedLoadCommand) reader.getFactory().create(UnsupportedLoadCommand.class);
		command.initUnsupportedLoadCommand(reader, type);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public UnsupportedLoadCommand() {
	}

	private void initUnsupportedLoadCommand(FactoryBundledWithBinaryReader reader, int type)
			throws IOException {
		initLoadCommand(reader);
		this.type = type;
	}

	@Override
	public String getCommandName() {
		return "Unsupported Load Command Type = 0x" + Integer.toHexString(type);
	}

	@Override
	public void markup(MachHeader header, FlatProgramAPI api, Address baseAddress, boolean isBinary,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		updateMonitor(monitor);
		if (isBinary) {
			try {
				createFragment(api, baseAddress, parentModule);
				Address address = baseAddress.getNewAddress(getStartIndex());
				api.createData(address, toDataType());
			}
			catch (Exception e) {
				log.appendMsg("Unable to create " + getCommandName() + " - " + e.getMessage());
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getCommandName(), 0);
		struct.add(DWORD, "cmd", null);
		struct.add(DWORD, "cmdsize", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
