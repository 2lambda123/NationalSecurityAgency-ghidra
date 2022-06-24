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
package ghidra.app.plugin.core.debug.platform.lldb;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

public class LldbX86DebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_X86 = new LanguageID("x86:LE:32:default");
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");
	protected static final CompilerSpecID COMP_ID_GCC = new CompilerSpecID("gcc");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("windows");

	protected static class LldbI386MacosOffer extends DefaultDebuggerMappingOffer {
		public LldbI386MacosOffer(TargetProcess process) {
			super(process, 100, "LLDB on macOS i386", LANG_ID_X86, COMP_ID_GCC, Set.of());
		}
	}

	protected static class LldbI386LinuxOffer extends DefaultDebuggerMappingOffer {
		public LldbI386LinuxOffer(TargetProcess process) {
			super(process, 100, "LLDB on Linux i386", LANG_ID_X86, COMP_ID_GCC, Set.of());
		}
	}

	// TODO
	protected static class LldbI386WindowsOffer extends DefaultDebuggerMappingOffer {
		public LldbI386WindowsOffer(TargetProcess process) {
			super(process, 100, "LLDB on Windows i386", LANG_ID_X86, COMP_ID_VS,
				Set.of());
		}
	}

	protected static class LldbI386X86_64MacosOffer extends DefaultDebuggerMappingOffer {
		public LldbI386X86_64MacosOffer(TargetProcess process) {
			super(process, 100, "LLDB on macOS x86_64", LANG_ID_X86_64, COMP_ID_GCC, Set.of());
		}
	}

	protected static class LldbI386X86_64LinuxOffer extends DefaultDebuggerMappingOffer {
		public LldbI386X86_64LinuxOffer(TargetProcess process) {
			super(process, 100, "LLDB on Linux x86_64", LANG_ID_X86_64, COMP_ID_GCC, Set.of());
		}
	}

	protected static class LldbI386X86_64WindowsOffer extends DefaultDebuggerMappingOffer {
		public LldbI386X86_64WindowsOffer(TargetProcess process) {
			super(process, 100, "LLDB on Windows x64", LANG_ID_X86_64, COMP_ID_VS,
				Set.of());
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetObject target,
			boolean includeOverrides) {
		if (!(target instanceof TargetProcess)) {
			return Set.of();
		}
		TargetProcess process = (TargetProcess) target;
		if (!env.getDebugger().toLowerCase().contains("lldb")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		boolean is32Bit = arch.contains("x86-32") || arch.contains("i386") ||
			arch.contains("x86_32");
		boolean is64Bit = arch.contains("x86-64") || arch.contains("x64-32") ||
			arch.contains("x86_64") || arch.contains("x64_32") || arch.contains("i686");
		String os = env.getOperatingSystem();
		if (os.contains("macos")) {
			if (is64Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386X86_64MacosOffer(process));
			}
			else if (is32Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386MacosOffer(process));
			}
			else {
				return Set.of();
			}
		}
		else if (os.contains("Linux") || os.contains("linux")) {
			if (is64Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386X86_64LinuxOffer(process));
			}
			else if (is32Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386LinuxOffer(process));
			}
			else {
				return Set.of();
			}
		}
		else if (os.contains("windows")) {
			if (is64Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386X86_64WindowsOffer(process));
			}
			else if (is32Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbI386WindowsOffer(process));
			}
			else {
				return Set.of();
			}
		}
		return Set.of();
	}
}
