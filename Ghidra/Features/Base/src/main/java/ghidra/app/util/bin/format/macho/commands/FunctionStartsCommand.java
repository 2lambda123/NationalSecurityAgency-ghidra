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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.address.Address;

/**
 * Represents a LC_FUNCTION_STARTS command.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class FunctionStartsCommand extends LinkEditDataCommand {
	
	static FunctionStartsCommand createFunctionStartsCommand(FactoryBundledWithBinaryReader reader)
			throws IOException {
		FunctionStartsCommand command =
			(FunctionStartsCommand) reader.getFactory().create(FunctionStartsCommand.class);
		command.initLinkEditDataCommand(reader);
		return command;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public FunctionStartsCommand() {
	}

	/**
	 * Finds the {@link List} of function start addresses
	 * 
	 * @param provider The provider that contains the function start addresses.  This could be a
	 *   different provider than the one that contains the load command.
	 * @param textSegmentAddr The {@link Address} of the function starts' __TEXT segment
	 * @return The {@link List} of function start addresses
	 * @throws IOException if there was an issue reading bytes
	 */
	public List<Address> findFunctionStartAddrs(ByteProvider provider, Address textSegmentAddr)
			throws IOException {
		List<Address> addrs = new ArrayList<>();
		Address current = textSegmentAddr;
		for (long offset : findFunctionStartOffsets(provider)) {
			current = current.add(offset);
			addrs.add(current);
		}

		return addrs;
	}

	/**
	 * Finds the {@link List} of function start offsets
	 * 
	 * @param provider The provider that contains the function start offsets.  This could be a
	 *   different provider than the one that contains the load command.
	 * @return The {@link List} of function start offsets
	 * @throws IOException if there was an issue reading bytes
	 */
	private List<Long> findFunctionStartOffsets(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(getDataOffset());

		List<Long> offsets = new ArrayList<>();
		while (true) {
			long offset = LEB128.readAsLong(reader, false);
			if (offset == 0) {
				break;
			}
			offsets.add(offset);
		}

		return offsets;
	}
}
