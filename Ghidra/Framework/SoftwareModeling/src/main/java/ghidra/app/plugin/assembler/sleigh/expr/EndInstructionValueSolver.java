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
package ghidra.app.plugin.assembler.sleigh.expr;

import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.expression.EndInstructionValue;

/**
 * "Solves" expressions of {@code inst_next}
 *
 * Works like the constant solver, but takes the value of {@code inst_next}, which is given by the
 * assembly address and the resulting instruction length.
 *
 * NOTE: This solver requires backfill.
 */
public class EndInstructionValueSolver extends AbstractExpressionSolver<EndInstructionValue> {

	public EndInstructionValueSolver() {
		super(EndInstructionValue.class);
	}

	@Override
	public AssemblyResolution solve(EndInstructionValue iv, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) {
		throw new AssertionError(
			"INTERNAL: Should never be asked to solve for " + AssemblyTreeResolver.INST_NEXT);
	}

	@Override
	public MaskedLong getValue(EndInstructionValue iv, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur)
			throws NeedsBackfillException {
		Long instNext = vals.get(AssemblyTreeResolver.INST_NEXT);
		if (instNext == null) {
			throw new NeedsBackfillException(AssemblyTreeResolver.INST_NEXT);
		}
		return MaskedLong.fromLong(vals.get(AssemblyTreeResolver.INST_NEXT));
	}

	@Override
	public int getInstructionLength(EndInstructionValue iv, Map<Integer, Object> res) {
		return 0;
	}

	@Override
	public MaskedLong valueForResolution(EndInstructionValue exp, AssemblyResolvedConstructor rc) {
		// Would need to pass in symbol values, and perhaps consider child resolutions.
		throw new UnsupportedOperationException(
			"The solver should never ask for this value given a resolved constructor.");
	}
}
