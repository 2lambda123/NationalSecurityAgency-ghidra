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
package ghidra.app.util.bin.format.dwarf4.next.sectionprovider;

import java.util.List;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Fetches DWARF sections from a normal program using simple Ghidra memory blocks. 
 */
public class BaseSectionProvider implements DWARFSectionProvider {
	protected Program program;
	protected List<String> sectionPrefixes = getSectionPrefixSearchList();

	public static BaseSectionProvider createSectionProviderFor(Program program,
			TaskMonitor monitor) {
		return new BaseSectionProvider(program);
	}

	public BaseSectionProvider(Program program) {
		this.program = program;
	}

	protected List<String> getSectionPrefixSearchList() {
		return List.of(".", "_", "__");
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName, TaskMonitor monitor)
			throws IOException {

		MemoryBlock block = getSection(sectionName);
		if (block != null && block.isInitialized()) {
			// NOTE: MemoryByteProvider instances don't need to be closed(), so we don't
			// track them here
			return MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(), block);
		}

		return null;
	}

	@Override
	public boolean hasSection(String... sectionNames) {
		for (String sectionName : sectionNames) {
			if (getSection(sectionName) == null) {
				return false;
			}
		}
		return true;
	}

	protected MemoryBlock getSection(String sectionName) {
		MemoryBlock block = program.getMemory().getBlock(sectionName);
		if (block == null) {
			for (String prefix : sectionPrefixes) {
				block = program.getMemory().getBlock(prefix + sectionName);
				if (block != null) {
					break;
				}
			}
		}
		return block;
	}

	@Override
	public void close() {
		// nothing
	}

}
