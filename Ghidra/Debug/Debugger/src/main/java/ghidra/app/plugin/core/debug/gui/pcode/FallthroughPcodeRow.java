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
package ghidra.app.plugin.core.debug.gui.pcode;

import ghidra.program.model.pcode.PcodeOp;

public class FallthroughPcodeRow implements PcodeRow {
	private final int sequence;
	private final boolean isNext;
	private final String label;

	public FallthroughPcodeRow(int sequence, boolean isNext, String label) {
		this.sequence = sequence;
		this.isNext = isNext;
		this.label = label;
	}

	@Override
	public int getSequence() {
		return sequence;
	}

	@Override
	public String getLabel() {
		return label;
	}

	@Override
	public String getCode() {
		return "(fall-through)";
	}

	@Override
	public boolean isNext() {
		return isNext;
	}

	@Override
	public PcodeOp getOp() {
		return null;
	}
}
