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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the COFF Auxiliary Symbol data structure.
 * <br>
 * <pre>
 * typedef union _IMAGE_AUX_SYMBOL {
 *     struct {
 *         DWORD    TagIndex;                      // struct, union, or enum tag index
 *         union {
 *             struct {
 *                 WORD    Linenumber;             // declaration line number
 *                 WORD    Size;                   // size of struct, union, or enum
 *             } LnSz;
 *            DWORD    TotalSize;
 *         }Misc;
 *         union {
 *             struct {                            // if ISFCN, tag, or .bb
 *                 DWORD    PointerToLinenumber;
 *                 DWORD    PointerToNextFunction;
 *             } Function;
 *             struct {                            // if ISARY, up to 4 dimen.
 *                 WORD     Dimension[4];
 *             } Array;
 *         } FcnAry;
 *         WORD    TvIndex;                        // tv index
 *     } Sym;
 *     struct {
 *         BYTE    Name[IMAGE_SIZEOF_SYMBOL];
 *     } File;
 *     struct {
 *         DWORD   Length;                         // section length
 *         WORD    NumberOfRelocations;            // number of relocation entries
 *         WORD    NumberOfLinenumbers;            // number of line numbers
 *         DWORD   CheckSum;                       // checksum for communal
 *         SHORT   Number;                         // section number to associate with
 *         BYTE    Selection;                      // communal selection type
 *     } Section;
 * } IMAGE_AUX_SYMBOL;
 * </pre>
 */
public class DebugCOFFSymbolAux implements StructConverter {
    public final static byte IMAGE_SIZEOF_AUX_SYMBOL = 18;

    private AuxSym sym;
    private AuxFile file;
    private AuxSection section;

	DebugCOFFSymbolAux(BinaryReader reader, int index, DebugCOFFSymbol symbol) throws IOException {
		switch (symbol.getStorageClass()) {
			case DebugCOFFSymbol.IMAGE_SYM_CLASS_FILE:
				file = new AuxFile(reader, index);
				break;
			case DebugCOFFSymbol.IMAGE_SYM_CLASS_EXTERNAL:
			case DebugCOFFSymbol.IMAGE_SYM_CLASS_FUNCTION:
				sym = new AuxSym(reader, index);
				break;
			case DebugCOFFSymbol.IMAGE_SYM_CLASS_STATIC:
				section = new AuxSection(reader, index);
				break;
//           case IMAGE_SYM_CLASS_CLR_TOKEN:
//               break:
			default:
				// unhandled aux symbol...
				break;
		}
    }

	/**
	 * @see java.lang.Object#toString()
	 */
    @Override
    public String toString() {
        if (file != null) {
            return file.getName();
        }
        else if (sym != null) {
            return  "Tag="+Integer.toHexString(sym.getTagIndex())+"  "+
                    "TvIndex="+Integer.toHexString(sym.getTvIndex());
//TODO:
//there are other cases here!
        }
        else if (section != null) {
            return  "Section="+Integer.toHexString(section.getNumber())+"  "+
                    "Len="+Integer.toHexString(section.getLength())+"  "+
                    "NumOfRelocs="+section.getNumberOfRelocations()+"  "+
                    "NumOfLineNums="+section.getNumberOfLinenumbers()+"  "+
                    "Checksum="+Integer.toHexString(section.getCheckSum());
        }
        return super.toString();
    }

    @Override
	public DataType toDataType() throws DuplicateNameException, IOException {
    	String structureName = StructConverterUtil.parseName(DebugCOFFSymbolAux.class);
    	Structure structure = new StructureDataType(structureName, IMAGE_SIZEOF_AUX_SYMBOL);
    	/*
    	if (sym != null) {
    		structure.add(sym.toDataType());
    	}
    	if (file != null) {
    		structure.add(file.toDataType());
    	}
    	if (section != null) {
    		structure.add(section.toDataType());
    	}
    	*/
    	return structure;
    }

	public static class AuxSym implements StructConverter {
        private int      tagIndex;
        private short    miscLnSzLinenumber;
        private short    miscLnSzSize;
        private int      miscTotalSize;
        private int      fncAryFunctionPointerToLinenumber;
        private int      fncAryFunctionPointerToNextFunction;
        private short [] fncAryArrayDimension = new short[4];
        private short    tvIndex;

		private AuxSym(BinaryReader reader, int index) throws IOException {
            tagIndex = reader.readInt(index); index += BinaryReader.SIZEOF_INT;

            miscLnSzLinenumber = reader.readShort(index);
            miscLnSzSize       = reader.readShort(index + BinaryReader.SIZEOF_SHORT);
            miscTotalSize      = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;

            fncAryFunctionPointerToLinenumber   = reader.readInt(index);
            fncAryFunctionPointerToNextFunction = reader.readInt(index + BinaryReader.SIZEOF_INT);
            fncAryArrayDimension                = reader.readShortArray(index, 4); index += (4 * BinaryReader.SIZEOF_SHORT);

            tvIndex = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        }


        int getTagIndex() {
            return tagIndex;
        }
        short getMiscLnSzLinenumber() {
            return miscLnSzLinenumber;
        }
        short getMiscLnSzSize() {
            return miscLnSzSize;
        }
        int getMiscTotalSize() {
            return miscTotalSize;
        }
        int getFncAryFunctionPointerToLinenumber() {
            return fncAryFunctionPointerToLinenumber;
        }
        int getFncAryFunctionPointerToNextFunction() {
            return fncAryFunctionPointerToNextFunction;
        }
        short [] getFncAryArrayDimension() {
            return fncAryArrayDimension;
        }
        short getTvIndex() {
            return tvIndex;
        }
        @Override
		public DataType toDataType() throws DuplicateNameException, IOException {
        	return StructConverterUtil.toDataType(this);
        }
    }

	public static class AuxFile implements StructConverter {
        private String name;

		private AuxFile(BinaryReader reader, int index) throws IOException {
			name = reader.readAsciiString(index, DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL).trim();
        }

        String getName() {
            return name;
        }
        @Override
		public DataType toDataType() throws DuplicateNameException, IOException {
        	String structureName = StructConverterUtil.parseName(DebugCOFFSymbolAux.class);
        	Structure structure = new StructureDataType(structureName, 0);
        	structure.add(STRING, DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL, "name", null);
        	return structure;
        }
    }

	public static class AuxSection implements StructConverter {
        private int   length;
        private short numberOfRelocations;
        private short numberOfLinenumbers;
        private int   checkSum;
        private short number;
        private byte  selection;

		private AuxSection(BinaryReader reader, int index) throws IOException {
            length              = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;
            numberOfRelocations = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
            numberOfLinenumbers = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
            checkSum            = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;
            number              = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
            selection           = reader.readByte (index); index += BinaryReader.SIZEOF_BYTE;
        }

        int getLength() {
            return length;
        }
        int getNumberOfRelocations() {
            return numberOfRelocations;
        }
        int getNumberOfLinenumbers() {
            return numberOfLinenumbers;
        }
        int getCheckSum() {
            return checkSum;
        }
        int getNumber() {
            return number;
        }
        int getSelection() {
            return selection;
        }
        @Override
		public DataType toDataType() throws DuplicateNameException, IOException {
        	return StructConverterUtil.toDataType(this);
        }
    }
}

