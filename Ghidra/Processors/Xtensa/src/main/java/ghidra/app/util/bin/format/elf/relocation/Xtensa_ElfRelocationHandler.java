package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.NotFoundException;

public class Xtensa_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_XTENSA ||
				elf.e_machine() == Xtensa_ElfRelocationConstants.EM_XTENSA_OLD;
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {
		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return RelocationResult.FAILURE;
		}

		int type=relocation.getType();
		if (Xtensa_ElfRelocationConstants.R_XTENSA_NONE == type) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend = relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);
		long offset = relocationAddress.getOffset();
		long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		ElfSymbol sym = null;
		long symbolValue = 0;
		String symbolName = null;

		int symbolIndex = relocation.getSymbolIndex();
		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}

		if (null != sym) {
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
		}

		//int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch(type) {
		case Xtensa_ElfRelocationConstants.R_XTENSA_32:
			markAsWarning(program, relocationAddress, "R_XTENSA_32",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_RTLD:
			markAsWarning(program, relocationAddress, "R_XTENSA_RTLD",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_GLOB_DAT:
			markAsWarning(program, relocationAddress, "R_XTENSA_GLOB_DAT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_JMP_SLOT:
			markAsWarning(program, relocationAddress, "R_XTENSA_JMP_SLOT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_RELATIVE:
			markAsWarning(program, relocationAddress, "R_XTENSA_RELATIVE",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_PLT:
			markAsWarning(program, relocationAddress, "R_XTENSA_PLT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_OP0:
			markAsWarning(program, relocationAddress, "R_XTENSA_OP0",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_OP1:
			markAsWarning(program, relocationAddress, "R_XTENSA_OP1",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_OP2:
			markAsWarning(program, relocationAddress, "R_XTENSA_OP2",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_ASM_EXPAND:
			markAsWarning(program, relocationAddress, "R_XTENSA_ASM_EXPAND",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_ASM_SIMPLIFY:
			markAsWarning(program, relocationAddress, "R_XTENSA_ASM_SIMPLIFY",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_GNU_VTINHERIT:
			markAsWarning(program, relocationAddress, "R_XTENSA_GNU_VTINHERIT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_GNU_VTENTRY:
			markAsWarning(program, relocationAddress, "R_XTENSA_GNU_VTENTRY",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_DIFF8:
			markAsWarning(program, relocationAddress, "R_XTENSA_DIFF8",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_DIFF16:
			markAsWarning(program, relocationAddress, "R_XTENSA_DIFF16",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_DIFF32:
			markAsWarning(program, relocationAddress, "R_XTENSA_DIFF32",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT0_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT0_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT1_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT1_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT2_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT2_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT3_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT3_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT4_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT4_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT5_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT5_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT6_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT6_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT7_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT7_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT8_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT8_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT9_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT9_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT10_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT10_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT11_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT11_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT12_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT12_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT13_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT13_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT14_OP:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT14_OP",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT0_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT0_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT1_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT1_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT2_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT2_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT3_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT3_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT4_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT4_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT5_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT5_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT6_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT6_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT7_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT7_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT8_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT8_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT9_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT9_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT10_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT10_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT11_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT11_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT12_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT12_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT13_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT13_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		case Xtensa_ElfRelocationConstants.R_XTENSA_SLOT14_ALT:
			markAsWarning(program, relocationAddress, "R_XTENSA_SLOT14_ALT",
					symbolName, symbolIndex, "TODO, needs support ",
					elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		default:
			markAsUnhandled(program, relocationAddress, type, symbolIndex,
					symbolName, elfRelocationContext.getLog());
			return RelocationResult.SKIPPED;
		}
		//return new RelocationResult(Status.APPLIED, byteLength);
	}

}
