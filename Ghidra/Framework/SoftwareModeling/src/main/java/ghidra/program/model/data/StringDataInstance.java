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
package ghidra.program.model.data;

import static ghidra.program.model.data.EndianSettingsDefinition.ENDIAN;
import static ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER;
import static ghidra.program.model.data.StringLayoutEnum.*;
import static ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import generic.stl.Pair;
import ghidra.docking.settings.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.*;
import ghidra.util.*;

/**
 * Represents an instance of a string in a {@link MemBuffer}.
 * <p>
 * This class handles all the details of detecting a terminated string's length,
 * converting the bytes in the membuffer into a java native String, and converting
 * the raw String into a formatted human-readable version, according to the
 * various {@link SettingsDefinition}s attached to the string data location.
 * <p>
 */
public class StringDataInstance {
	/**
	 * Returns true if the {@link Data} instance is a 'string'.
	 *
	 * @param data {@link Data} instance to test, null ok.
	 * @return boolean true if string data.
	 */
	public static boolean isString(Data data) {
		if (data == null) {
			return false;
		}
		DataType dt = data.getBaseDataType();
		if (dt instanceof AbstractStringDataType) {
			return true;
		}
		if (dt instanceof Array) {
			ArrayStringable as = ArrayStringable.getArrayStringable(((Array) dt).getDataType());
			return (as != null) && as.hasStringValue(data);
		}
		return false;
	}

	public static boolean isChar(Data data) {
		if (data == null) {
			return false;
		}
		DataType dt = data.getBaseDataType();
		return (dt instanceof CharDataType) || (dt instanceof WideCharDataType) ||
			(dt instanceof WideChar16DataType) || (dt instanceof WideChar32DataType);
	}

	/**
	 * Returns a new {@link StringDataInstance} using the bytes in the data codeunit.
	 * <p>
	 * @param data {@link Data} item
	 * @return new {@link StringDataInstance}, never NULL.  See {@link #NULL_INSTANCE}.
	 */
	public static StringDataInstance getStringDataInstance(Data data) {
		if (data == null) {
			return NULL_INSTANCE;
		}
		DataType dt = data.getBaseDataType();
		if (dt instanceof AbstractStringDataType) {
			return ((AbstractStringDataType) dt).getStringDataInstance(data, data,
				data.getLength());
		}
		if (dt instanceof Array) {
			ArrayStringable arrayStringable =
				ArrayStringable.getArrayStringable(((Array) dt).getDataType());
			return arrayStringable.getStringDataInstance(data, data, data.getLength());
		}
		return NULL_INSTANCE;
	}

	/**
	 * Returns a new {@link StringDataInstance} using the bytes in the MemBuffer.
	 * <p>
	 * @param stringDataType {@link DataType} of the bytes in the buffer.
	 * @param buf memory buffer containing the bytes.
	 * @param settings the Settings object
	 * @param length the length of the data.
	 * @return new {@link StringDataInstance}, never NULL.  See {@link #NULL_INSTANCE}.
	 */
	public static StringDataInstance getStringDataInstance(DataType stringDataType, MemBuffer buf,
			Settings settings, int length) {
		if (stringDataType instanceof AbstractStringDataType) {
			return ((AbstractStringDataType) stringDataType).getStringDataInstance(buf, settings,
				length);
		}
		if (stringDataType instanceof Array &&
			((Array) stringDataType).getDataType() instanceof ArrayStringable) {
			stringDataType = ((Array) stringDataType).getDataType();
		}
		if (stringDataType instanceof ArrayStringable &&
			((ArrayStringable) stringDataType).hasStringValue(settings)) {
			return ((ArrayStringable) stringDataType).getStringDataInstance(buf, settings, length);
		}
		return NULL_INSTANCE;
	}

	//-----------------------------------------------------------------------------
	/**
	 * A {@link StringDataInstance} that represents a non-existent string.
	 * <p>
	 * Methods on this instance generally return null.
	 */
	public static final StringDataInstance NULL_INSTANCE = new StaticStringInstance(null, -1);

	public static final int MAX_STRING_LENGTH = 16 * 1024;

	public static final String DEFAULT_CHARSET_NAME = CharsetInfo.USASCII;

	public static final String UNKNOWN = "??";
	public static final String UNKNOWN_DOT_DOT_DOT = "??...";

	/**
	 * A string with a single char that is the Byte-Order-Mark character.
	 */
	private static final String BOM_RESULT_STR = "\ufeff";

	private static final int SIZEOF_PASCAL255_STR_LEN_FIELD = 1;
	private static final int SIZEOF_PASCAL64k_STR_LEN_FIELD = 2;

	private final String charsetName;
	private final int charSize;
	private final int paddedCharSize;
	private final StringLayoutEnum stringLayout;
	private final String translatedValue;
	private final Endian endianSetting;

	private boolean showTranslation;
	private RENDER_ENUM renderSetting;

	private int length;
	private final MemBuffer buf;

	protected StringDataInstance() {
		// default field values for Dummy subclass
		buf = null;
		charSize = 0;
		paddedCharSize = 0;
		charsetName = UNKNOWN;
		translatedValue = null;
		stringLayout = StringLayoutEnum.FIXED_LEN;
		endianSetting = null;
		renderSetting = RENDER_ENUM.ALL;
	}

	/**
	 * Creates a string instance using the data in the {@link MemBuffer} and the settings
	 * pulled from the {@link AbstractStringDataType string data type}.
	 *
	 * @param stringDataType {@link AbstractStringDataType} common string base data type.
	 * @param settings {@link Settings} attached to the data location.
	 * @param buf {@link MemBuffer} containing the data.
	 * @param length Length passed from the caller to the datatype.  -1 indicates a 'probe'
	 * trying to detect the length of an unknown string, otherwise it will be the length
	 * of the containing field of the data instance.
	 */
	public StringDataInstance(DataType dataType, Settings settings, MemBuffer buf, int length) {
		settings = (settings == null) ? SettingsImpl.NO_SETTINGS : settings;
		this.buf = buf;
		this.charsetName = getCharsetNameFromDataTypeOrSettings(dataType, settings);
		this.charSize = CharsetInfo.getInstance().getCharsetCharSize(charsetName);
		// NOTE: for now only handle padding for charSize == 1 
		this.paddedCharSize =
			charSize == 1 ? getDataOrganization(dataType).getCharSize() : charSize;
		this.stringLayout = getLayoutFromDataType(dataType);
		this.showTranslation = TRANSLATION.isShowTranslated(settings);
		this.translatedValue = TRANSLATION.getTranslatedValue(settings);
		this.renderSetting = RENDER.getEnumValue(settings);
		this.endianSetting = ENDIAN.getEndianess(settings, null);

		this.length = length;
	}

	private StringDataInstance(StringDataInstance copyFrom, StringLayoutEnum newLayout,
			MemBuffer newBuf, int newLen) {
		this.charSize = copyFrom.charSize;
		this.paddedCharSize = copyFrom.paddedCharSize;
		this.translatedValue = null;
		this.charsetName = copyFrom.charsetName;
		this.stringLayout = newLayout;
		this.showTranslation = false;
		this.renderSetting = copyFrom.renderSetting;
		this.length = newLen;
		this.buf = newBuf;
		this.endianSetting = copyFrom.endianSetting;
	}

	private static DataOrganization getDataOrganization(DataType dataType) {
		// The dataType should be correspond to the target program
		if (dataType != null) {
			DataTypeManager dtm = dataType.getDataTypeManager();
			if (dtm != null) {
				return dtm.getDataOrganization();
			}
		}
		return DataOrganizationImpl.getDefaultOrganization();
	}

	private static StringLayoutEnum getLayoutFromDataType(DataType dataType) {
		if (dataType instanceof AbstractStringDataType) {
			return ((AbstractStringDataType) dataType).getStringLayout();
		}
		return StringLayoutEnum.NULL_TERMINATED_BOUNDED;
	}

	private static String getCharsetNameFromDataTypeOrSettings(DataType dataType,
			Settings settings) {
		return (dataType instanceof DataTypeWithCharset)
				? ((DataTypeWithCharset) dataType).getCharsetName(settings)
				: DEFAULT_CHARSET_NAME;
	}

	/**
	 * Returns the string name of the charset.
	 *
	 * @return string charset name
	 */
	public String getCharsetName() {
		return charsetName;
	}

	/**
	 * Returns the address of the {@link MemBuffer}.
	 *
	 * @return {@link Address} of the MemBuffer.
	 */
	public Address getAddress() {
		return buf.getAddress();
	}

	private boolean isBadCharSize() {
		return (paddedCharSize < 1 || paddedCharSize > 8) ||
			!(charSize == 1 || charSize == 2 || charSize == 4) || (paddedCharSize < charSize);
	}

	private boolean isProbe() {
		return length == -1;
	}

	private boolean isAlreadyDeterminedFixedLen() {
		return length >= 0 && (stringLayout == StringLayoutEnum.FIXED_LEN);
	}

	public boolean isPascal() {
		return stringLayout == StringLayoutEnum.PASCAL_255 ||
			stringLayout == StringLayoutEnum.PASCAL_64k;
	}

	/**
	 * Returns the length of this string's data, in bytes.
	 *
	 * @return number of bytes in this string.
	 */
	public int getDataLength() {
		return length;
	}

	/**
	 * Returns the length, in bytes, of the string data object contained in the
	 * {@link MemBuffer}, or -1 if the length could not be determined.
	 * <p>
	 * This is not the same as the number of characters in the string, or the number of bytes
	 * occupied by the characters.  For instance, pascal strings have a 1 or 2 byte length
	 * field that increases the size of the string data object beyond the characters in the
	 * string, and null terminated strings have don't include the null character, but its
	 * presence is included in the size of the string object.
	 * <p>
	 * For length-specified string data types that do not use null-terminators and with a
	 * known data instance length (ie. not a probe), this method just returns the
	 * value specified in the constructor {@code length} parameter, otherwise a null-terminator
	 * is searched for.
	 * <p>
	 * When searching for a null-terminator, the constructor {@code length} parameter will
	 * be respected or ignored depending on the {@link StringLayoutEnum}.
	 * <p>
	 * When the length parameter is ignored (ie. "unbounded" searching), the search is
	 * limited to {@link #MAX_STRING_LENGTH} bytes.
	 * <p>
	 * The MemBuffer's endian'ness is used to determine which end of the padded character
	 * field contains our n-bit character which will be tested for null-ness.  (not the
	 * endian'ness of the character set name - ie. "UTF-16BE")
	 *
	 * @return length of the string (NOT including null term if null term probe), in bytes,
	 * or -1 if no terminator found.
	 */
	public int getStringLength() {
		if (stringLayout.isPascal()) {
			return getPascalLength();
		}
		else if (isBadCharSize() || (buf == null) || isAlreadyDeterminedFixedLen()) {
			return length;
		}
		else {
			return getNullTerminatedLength();
		}
	}

	private int getNullTerminatedLength() {
		int localLen = length;
		boolean localNT = stringLayout.isNullTerminated();
		if (isProbe() || stringLayout == StringLayoutEnum.NULL_TERMINATED_UNBOUNDED) {
			localLen = MAX_STRING_LENGTH;
			localNT = true;
		}

		int internalCharOffset = buf.isBigEndian() ? paddedCharSize - charSize : 0;
		byte[] charBuf = new byte[charSize];
		for (int offset = 0; offset < localLen; offset += paddedCharSize) {
			try {
				if (!readChar(charBuf, offset + internalCharOffset)) {
					break;
				}
				if (localNT && isNullChar(charBuf)) {
					return offset + paddedCharSize;
				}
			}
			catch (AddressOutOfBoundsException exc) {
				return (stringLayout == StringLayoutEnum.NULL_TERMINATED_UNBOUNDED) ? -1 : offset;
			}
		}

		return (stringLayout == StringLayoutEnum.NULL_TERMINATED_UNBOUNDED) ? -1 : length;
	}

	/**
	 * Returns true if the string has a trailing NULL character within the data instance's
	 * bounds.
	 *
	 * @return boolean true if there is a trailing NULL character.
	 */
	public boolean hasNullTerminator() {

		if (!isPascal()) {
			String str = getStringValueNoTrim();
			return (str != null) && (str.length() > 0) && str.charAt(str.length() - 1) == 0;
		}
		return false;
	}

	private int getPascalLength() {
		try {
			switch (stringLayout) {
				case PASCAL_255:
					return SIZEOF_PASCAL255_STR_LEN_FIELD +
						(buf.getUnsignedByte(0) * paddedCharSize);
				case PASCAL_64k:
					return SIZEOF_PASCAL64k_STR_LEN_FIELD +
						(buf.getUnsignedShort(0) * paddedCharSize);
				default:
					return -1;
			}
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "PascalString error: " + e.getMessage());
			return -1;
		}
	}

	private boolean readChar(byte[] charBuf, int offset) {
		return buf.getBytes(charBuf, offset) == charBuf.length;
	}

	private boolean isNullChar(byte[] charBuf) {
		for (byte element : charBuf) {
			if (element != 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns the string contained in the specified {@link MemBuffer}, or null if
	 * all the bytes of the string could not be read.
	 * <p>
	 * This method deals in characters of size {@link #charSize}, that might be
	 * {@link #paddedCharSize padded} to a larger size.  The raw n-byte characters
	 * are converted into a Java String using a Java {@link Charset} or by
	 * using a custom Ghidra conversion.  (see convertBytesToStringCustomCharset)
	 * <p>
	 * The MemBuffer's endian'ness is used to determine which end of the
	 * {@link #paddedCharSize padded } field contains our {@link #charSize}
	 * character bytes which will be used to create the java String.
	 *
	 * @return String containing the characters in buf or null if unable to read all
	 * {@code length} bytes from the membuffer.
	 */
	public String getStringValue() {
		String str = getStringValueNoTrim();

		return (str != null) && !isPascal() ? trimNulls(str) : str;
	}

	private String getStringValueNoTrim() {
		if (isProbe() || isBadCharSize()) {
			return null;
		}
		byte[] stringBytes = convertPaddedToUnpadded(getStringBytes());
		if (stringBytes == null) {
			return StringDataInstance.UNKNOWN_DOT_DOT_DOT;
		}
		AdjustedCharsetInfo aci = getAdjustedCharsetInfo(stringBytes);
		String str = convertBytesToString(stringBytes, aci);

		return str;
	}

	private byte[] getStringBytes() {
		return isPascal() ? getPascalCharBytes() : getNormalStringCharBytes();
	}

	private byte[] getNormalStringCharBytes() {
		int strLength = getStringLength();

		return getBytesFromMemBuff(buf, strLength >= 0 ? strLength : length);
	}

	private byte[] getPascalCharBytes() {
		try {
			int len;
			int offset;
			switch (stringLayout) {
				case PASCAL_255:
					len = buf.getUnsignedByte(0) * paddedCharSize;
					offset = SIZEOF_PASCAL255_STR_LEN_FIELD;
					break;
				case PASCAL_64k:
					len = buf.getUnsignedShort(0) * paddedCharSize;
					offset = SIZEOF_PASCAL64k_STR_LEN_FIELD;
					break;
				default:
					throw new IllegalArgumentException();
			}
			WrappedMemBuffer pascalBuf = new WrappedMemBuffer(buf, offset);
			return getBytesFromMemBuff(pascalBuf, len);
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "PascalString error: " + e.getMessage());
		}
		return null;
	}

	private boolean isValidOffcutOffset(int offcutBytes) {
		int minValid;
		switch (stringLayout) {
			case PASCAL_255:
				minValid = SIZEOF_PASCAL255_STR_LEN_FIELD;
			case PASCAL_64k:
				minValid = SIZEOF_PASCAL64k_STR_LEN_FIELD;
			default:
				minValid = 0;
		}
		return offcutBytes >= minValid && offcutBytes < length;
	}

	private int getCharOffset(int charCount) {
		int charBytes = charCount * charSize;
		switch (stringLayout) {
			case PASCAL_255:
				return Math.max(0, SIZEOF_PASCAL255_STR_LEN_FIELD + charBytes);
			case PASCAL_64k:
				return Math.max(0, SIZEOF_PASCAL64k_STR_LEN_FIELD + charBytes);
			default:
				return charBytes;
		}
	}

	private StringLayoutEnum getOffcutLayout() {
		switch (stringLayout) {
			case PASCAL_255:
			case PASCAL_64k:
				return StringLayoutEnum.FIXED_LEN;
			default:
				return stringLayout;
		}
	}

	private byte[] getBytesFromMemBuff(MemBuffer memBuffer, int copyLen) {
		// round copyLen down to multiple of paddedCharSize
		copyLen &= ~(paddedCharSize - 1);

		byte[] bytes = new byte[copyLen];
		if (memBuffer.getBytes(bytes, 0) != bytes.length) {
			return null;
		}
		return bytes;
	}

	private byte[] convertPaddedToUnpadded(byte[] paddedBytes) {
		if (paddedCharSize == charSize || paddedBytes == null) {
			return paddedBytes;
		}

		byte[] unpaddedBytes = new byte[(paddedBytes.length / paddedCharSize) * charSize];
		for (int srcOffset = buf.isBigEndian() ? paddedCharSize - charSize : 0, destOffset =
			0; srcOffset < paddedBytes.length; srcOffset += paddedCharSize, destOffset +=
				charSize) {
			System.arraycopy(paddedBytes, srcOffset, unpaddedBytes, destOffset, charSize);
		}

		return unpaddedBytes;
	}

	private Endian getMemoryEndianness() {
		return buf.isBigEndian() ? Endian.BIG : Endian.LITTLE;
	}

	private String convertBytesToString(byte[] bytes, AdjustedCharsetInfo aci) {
		Charset cs = Charset.isSupported(aci.charsetName) ? Charset.forName(aci.charsetName) : null;
		return (cs != null)
				? new String(bytes, aci.byteStartOffset, bytes.length - aci.byteStartOffset, cs)
				: convertBytesToStringCustomCharset(bytes, aci);
	}

	private AdjustedCharsetInfo getAdjustedCharsetInfo(byte[] bytes) {
		AdjustedCharsetInfo result = new AdjustedCharsetInfo(charsetName);
		if (CharsetInfo.isBOMCharset(charsetName)) {
			result.endian = getEndiannessFromBOM(bytes, charSize);
			if (result.endian != null) {
				// skip the BOM char when creating the string
				result.byteStartOffset = charSize;
			}
			if (result.endian == null) {
				result.endian = endianSetting;
			}
			if (result.endian == null) {
				result.endian = getMemoryEndianness();
			}
			// add "LE" or "BE" to end of charset's name depending
			// of the discovered endianness of the string
			result.charsetName += result.endian.toShortString();
		}
		if (result.endian == null) {
			result.endian = getMemoryEndianness();
		}
		return result;
	}

	private byte[] convertStringToBytes(String s, AdjustedCharsetInfo aci) {
		Charset cs = Charset.isSupported(aci.charsetName) ? Charset.forName(aci.charsetName) : null;
		return (cs != null) ? s.getBytes(cs) : null;
	}

	private static DataConverter getDataConverter(Endian endian) {
		return endian == Endian.BIG ? BigEndianDataConverter.INSTANCE
				: LittleEndianDataConverter.INSTANCE;
	}

	/*
	 * Converts a byte array to String based on a custom Ghidra charset name.
	 */
	private static String convertBytesToStringCustomCharset(byte[] bytes, AdjustedCharsetInfo aci) {
		switch (aci.charsetName) {
			case "UTF-32LE":
			case "UTF-32BE":
				// fall-back because real jvm supplied UTF-32 Charset isn't guaranteed to be present
				DataConverter dc = getDataConverter(aci.endian);
				int[] codePoints = new int[(bytes.length - aci.byteStartOffset) / 4];
				for (int i = 0; i < codePoints.length; i++) {
					codePoints[i] = dc.getInt(bytes, aci.byteStartOffset + (i * 4));
					if (codePoints[i] < 0 || codePoints[i] > Character.MAX_CODE_POINT) {
						codePoints[i] = StringUtilities.UNICODE_REPLACEMENT;
					}
				}
				return new String(codePoints, 0, codePoints.length);
		}
		return null;
	}

	private static Endian getEndiannessFromBOM(byte[] bytes, int charSize) {
		if (bytes.length < charSize) {
			return null;
		}
		int be_val = (int) BigEndianDataConverter.INSTANCE.getValue(bytes, charSize);
		switch (be_val) {
			case StringUtilities.UNICODE_BE_BYTE_ORDER_MARK:
				return Endian.BIG;
			case StringUtilities.UNICODE_LE16_BYTE_ORDER_MARK:
			case StringUtilities.UNICODE_LE32_BYTE_ORDER_MARK:
				return Endian.LITTLE;
		}
		return null;
	}

	/**
	 * Returns a formatted version of the string returned by {@link #getStringValue()}.
	 * <p>
	 * The resulting string will be formatted with quotes around the parts that contain
	 * plain ASCII alpha characters (and simple escape sequences), and out-of-range
	 * byte-ish values listed as comma separated hex-encoded values:
	 * <p>
	 * Example (quotes are part of result): {@code "Test\tstring",01,02,"Second\npart",00}
	 *
	 * @return formatted String
	 */
	public String getStringRepresentation() {

		if (isProbe() || isBadCharSize()) {
			return UNKNOWN;
		}

		if (showTranslation && translatedValue != null) {
			return getTranslatedStringRepresentation(translatedValue);
		}

		byte[] stringBytes = convertPaddedToUnpadded(getStringBytes());
		if (stringBytes == null) {
			return UNKNOWN_DOT_DOT_DOT;
		}
		AdjustedCharsetInfo aci = getAdjustedCharsetInfo(stringBytes);
		String stringValue = convertBytesToString(stringBytes, aci);
		if (stringValue == null) {
			return UNKNOWN_DOT_DOT_DOT;
		}

		// if we get the same number of characters out that we put into the decoder,
		// then its a good chance there is a one-to-one correspondence between original char
		// and decoded char.
		boolean canRecoverOriginalCharBytes =
			(stringValue.length() - aci.byteStartOffset) == (stringBytes.length / charSize);

		StringRenderBuilder strBuf = new StringRenderBuilder(charSize);

		stringValue = !isPascal() ? trimNulls(stringValue) : stringValue;
		if (stringValue.isEmpty() || (stringValue.length() == 1 && stringValue.charAt(0) == 0)) {
			// force the string renderer into "string" mode so we get empty quotes when done.
			strBuf.addString("");
		}

		// For each 32bit character in the java string try to add it to the StringRenderBuilder
		for (int i = 0, strLength = stringValue.length(); i < strLength;) {
			int codePoint = stringValue.codePointAt(i);
			byte[] originalCharBytes;
			if (canRecoverOriginalCharBytes) {
				originalCharBytes = new byte[charSize];
				System.arraycopy(stringBytes, i * charSize, originalCharBytes, 0, charSize);
			}
			else {
				// can't get original bytes, cheat and run the codePoint through the charset
				// to get what should be the same as the original bytes.
				String singleCharStr = new String(new int[] { codePoint }, 0, 1);
				originalCharBytes = convertStringToBytes(singleCharStr, aci);
			}

			if (StringUtilities.isControlCharacterOrBackslash(codePoint)) {
				strBuf.addString(StringUtilities.convertCodePointToEscapeSequence(codePoint));
			}
			else if (codePoint == 0x0000 && renderSetting != RENDER_ENUM.BYTE_SEQ) {
				strBuf.addEscapedChar('0');
			}
			else if (StringUtilities.isDisplayable(codePoint)) {
				strBuf.addCodePointChar(codePoint);
			}
			else if (StringUtilities.isUnicodeReplacementCodePoint(codePoint)) {
				// if this is a true decode error and we can recover the original bytes
				// render as byte seq.
				// Otherwise, display the <?> symbol.
				if (canRecoverOriginalCharBytes &&
					isMismatchedCharBytes(originalCharBytes, codePoint)) {
					strBuf.addByteSeq(originalCharBytes);
				}
				else {
					strBuf.addCodePointChar(codePoint);
				}
			}
			else {
				// not simple ascii, decide how to handle:
				// add the character to the string in a format depending on the
				// render settings.  ISO control chars are forced to be
				// escaped regardless of the render setting.
				RENDER_ENUM thisCharRenderSetting = renderSetting;
				if (thisCharRenderSetting == RENDER_ENUM.ALL) {
					if (codePoint <= 0x7f) {
						// render non-displayable, non-control-char ascii-ish bytes as bytes instead
						// of as escape sequences
						thisCharRenderSetting = RENDER_ENUM.BYTE_SEQ;
					}
					else if (Character.isISOControl(codePoint) || !Character.isDefined(codePoint)) {
						thisCharRenderSetting = RENDER_ENUM.ESC_SEQ;
					}
				}

				switch (thisCharRenderSetting) {
					case ALL:
						strBuf.addCodePointChar(codePoint);
						break;
					case BYTE_SEQ:
						strBuf.addByteSeq(originalCharBytes);
						break;
					case ESC_SEQ:
						strBuf.addEscapedCodePoint(codePoint);
						break;
				}
			}
			i += Character.charCount(codePoint);
		}
		String result = strBuf.toString();
		String prefix = "";
		if (charsetName.startsWith("UTF") && result.startsWith("\"")) {
			switch (charSize) {
				case 1:
					prefix = "u8";
					break;
				case 2:
					prefix = "u";
					break;
				case 4:
					prefix = "U";
					break;
			}
		}
		return prefix + result;
	}

	/**
	 * Trims trailing nulls off the end of the string.
	 *
	 * @param s String to trim
	 * @return new String without any trailing null chars.
	 */
	private String trimNulls(String s) {
		int lastGoodChar = s.length() - 1;
		while (lastGoodChar >= 0 && s.charAt(lastGoodChar) == 0) {
			lastGoodChar--;
		}
		return s.substring(0, lastGoodChar + 1);
	}

	/**
	 * Returns the value of the stored
	 * {@link TranslationSettingsDefinition#getTranslatedValue(Settings) translated settings}
	 * string.
	 * <p>
	 * @return previously translated string.
	 */
	public String getTranslatedValue() {
		return translatedValue;
	}

	/**
	 * Returns true if the user should be shown the translated value of the string instead
	 * of the real value.
	 *
	 * @return boolean true if should show previously translated value.
	 */
	public boolean isShowTranslation() {
		return showTranslation;
	}

	/**
	 * Convert a char value in memory into its canonical unicode representation, using
	 * attached charset and encoding information.
	 * <p>
	 * This implementation treats the char value as a 1 element long string and reuses the string
	 * logic to read it from memory using charset info.
	 *
	 * @return String containing the representation of the single char.
	 */
	public String getCharRepresentation() {
		if (length < charSize) {
			return UNKNOWN_DOT_DOT_DOT;
		}

		byte[] charBytes = convertPaddedToUnpadded(getStringBytes());
		if (charBytes == null) {
			return UNKNOWN_DOT_DOT_DOT;
		}

		AdjustedCharsetInfo aci = getAdjustedCharsetInfo(charBytes);
		String stringValue = convertBytesToString(charBytes, aci);
		if (stringValue == null) {
			return UNKNOWN_DOT_DOT_DOT;
		}

		if (stringValue.length() == 0) {
			if (aci.byteStartOffset == 0) {
				return UNKNOWN;
			}

			// If the byteStartOffset isn't zero it means the char was the unicode BOM.
			// Asking the Charset to decode it returned nothing, so force it.
			stringValue = BOM_RESULT_STR;
		}

		int codePoint = stringValue.codePointAt(0);
		RENDER_ENUM tmpRenderSetting = renderSetting;

		StringRenderBuilder strBuf =
			new StringRenderBuilder(charSize, StringRenderBuilder.SINGLE_QUOTE);
		if (StringUtilities.isControlCharacterOrBackslash(codePoint)) {
			strBuf.addString(StringUtilities.convertCodePointToEscapeSequence(codePoint));
		}
		else if (codePoint == 0x0000 && renderSetting != RENDER_ENUM.BYTE_SEQ) {
			strBuf.addEscapedChar('0');
		}
		else if (StringUtilities.isUnicodeReplacementCodePoint(codePoint) &&
			renderSetting != RENDER_ENUM.BYTE_SEQ) {
			strBuf.addCodePointChar(codePoint);
		}
		else if (StringUtilities.isDisplayable(codePoint)) {
			strBuf.addCodePointChar(codePoint);
		}
		else {
			// not simple ascii, decide how to handle:
			// add the character to the string in a format depending on the
			// render settings.  ISO control chars are forced to be
			// escaped regardless of the render setting.
			boolean alwaysNeedsEscaping = (renderSetting == RENDER_ENUM.ALL) &&
				(Character.isISOControl(codePoint) || !Character.isDefined(codePoint) ||
					codePoint == StringUtilities.UNICODE_BE_BYTE_ORDER_MARK);

			tmpRenderSetting = alwaysNeedsEscaping ? RENDER_ENUM.ESC_SEQ : renderSetting;

			switch (tmpRenderSetting) {
				case ALL:
					strBuf.addCodePointChar(codePoint);
					break;
				case ESC_SEQ:
					strBuf.addEscapedCodePoint(codePoint);
					break;
				case BYTE_SEQ:
					// BYTE_SEQ uses original bytes of char data, not the bytes produced by the charset
					strBuf.addByteSeq(charBytes);
					break;
			}

		}
		String prefix = "";
		if (charsetName.startsWith("UTF") && tmpRenderSetting != RENDER_ENUM.BYTE_SEQ) {
			switch (charSize) {
				case 1:
					prefix = "u8";
					break;
				case 2:
					prefix = "u";
					break;
				case 4:
					prefix = "U";
					break;
			}
		}

		return prefix + strBuf.toString();
	}

	private boolean isMismatchedCharBytes(byte[] originalCharBytes, int codePoint) {
		long originalValue = DataConverter.getInstance(buf.isBigEndian()).getValue(
			originalCharBytes, originalCharBytes.length);
		return originalValue != codePoint;
	}

	private static String getTranslatedStringRepresentation(String translatedString) {
		return "\u00BB" + translatedString + "\u00AB";
	}

	public String getLabel(String prefixStr, String abbrevPrefixStr, String defaultStr,
			DataTypeDisplayOptions options) {
		if (isProbe() || isBadCharSize()) {
			return defaultStr;
		}

		if (options.useAbbreviatedForm()) {
			// no data from the data instance is used, just its abbrev type prefix and its address
			return abbrevPrefixStr;
		}

		String str = getStringValue();
		if (str == null || str.length() == 0) {
			return prefixStr;
		}

		boolean needsUnderscore = false;
		StringBuilder buffer = new StringBuilder();
		for (int i = 0, strLength = str.length(); i < strLength &&
			buffer.length() < options.getLabelStringLength();) {
			int codePoint = str.codePointAt(i);
			if (StringUtilities.isDisplayable(codePoint) && (codePoint != ' ')) {
				if (needsUnderscore) {
					buffer.append('_');
					needsUnderscore = false;
				}
				buffer.appendCodePoint(codePoint);
			}
			else {
				needsUnderscore = true;
				// discard character
			}
			i += Character.charCount(codePoint);
		}
		return prefixStr + buffer.toString();
	}

	public String getOffcutLabelString(String prefixStr, String abbrevPrefixStr, String defaultStr,
			DataTypeDisplayOptions options, int byteOffset) {
		if (isBadCharSize() || isProbe()) {
			return defaultStr;
		}
		StringDataInstance sub = getByteOffcut(byteOffset);
		return sub.getLabel(prefixStr, abbrevPrefixStr, defaultStr, options);
	}

	/**
	 * Returns a new {@link StringDataInstance} that points to the string characters
	 * that start at {@code byteOffset} from the start of this instance.
	 * <p>
	 * If the requested offset is not valid, the base string instance (itself) will be returned
	 * instead of a new instance.
	 * <p>
	 * @param byteOffset number of bytes from start of data instance to start new instance.
	 * @return new StringDataInstance, or <code>this</code> if offset not valid.
	 */
	public StringDataInstance getByteOffcut(int byteOffset) {
		if (isBadCharSize() || isProbe() || !isValidOffcutOffset(byteOffset)) {
			return NULL_INSTANCE;
		}
		int newLength = Math.max(0, length - byteOffset);
		StringDataInstance sub = new StringDataInstance(this, getOffcutLayout(),
			new WrappedMemBuffer(buf, byteOffset), newLength);

		return sub;
	}

	/**
	 * Create a new {@link StringDataInstance} that points to a portion of this
	 * instance, starting at a character offset (whereever that may be) into the data.
	 * <p>
	 * @param offsetChars number of characters from the beginning of the string to start
	 * the new StringDataInstance.
	 * @return new {@link StringDataInstance} pointing to a subset of characters, or the
	 * <code>this</code> instance if there was an error.
	 */
	public StringDataInstance getCharOffcut(int offsetChars) {
		return getByteOffcut(getCharOffset(offsetChars));
	}

	/**
	 * Maps a {@link StringDataInstance}'s layout and charset info into the best String
	 * DataType that can handle this type of data instance.
	 * <p>
	 * An entry with a null charset name is equivalent to any charset.
	 *
	 */
	private static final Map<Pair<StringLayoutEnum, String>, DataType> dataTypeMap =
		new HashMap<>();
	static {
		dataTypeMap.put(new Pair<>(PASCAL_255, null), PascalString255DataType.dataType);
		dataTypeMap.put(new Pair<>(PASCAL_64k, null), PascalStringDataType.dataType);
		dataTypeMap.put(new Pair<>(FIXED_LEN, null), StringDataType.dataType);
		dataTypeMap.put(new Pair<>(NULL_TERMINATED_BOUNDED, null), StringDataType.dataType);
		dataTypeMap.put(new Pair<>(NULL_TERMINATED_UNBOUNDED, null),
			TerminatedStringDataType.dataType);

		dataTypeMap.put(new Pair<>(PASCAL_64k, CharsetInfo.UTF16), PascalUnicodeDataType.dataType);

		dataTypeMap.put(new Pair<>(FIXED_LEN, CharsetInfo.UTF8), StringUTF8DataType.dataType);
		dataTypeMap.put(new Pair<>(FIXED_LEN, CharsetInfo.UTF16), UnicodeDataType.dataType);
		dataTypeMap.put(new Pair<>(FIXED_LEN, CharsetInfo.UTF32), Unicode32DataType.dataType);

		dataTypeMap.put(new Pair<>(NULL_TERMINATED_UNBOUNDED, CharsetInfo.UTF16),
			TerminatedUnicodeDataType.dataType);
		dataTypeMap.put(new Pair<>(NULL_TERMINATED_UNBOUNDED, CharsetInfo.UTF32),
			TerminatedUnicode32DataType.dataType);
	}

	/**
	 * Maps a {@link StringDataInstance} (this type) to the String DataType that best
	 * can handle this type of data.
	 * <p>
	 * I dare myself to type Type one more time.
	 * <p>
	 * @return {@link DataType}, defaulting to {@link StringDataType} if no direct match found.
	 */
	public DataType getStringDataTypeGuess() {
		DataType result = dataTypeMap.get(new Pair<>(stringLayout, charsetName));
		if (result == null) {
			result = dataTypeMap.get(new Pair<>(stringLayout, null));
		}
		if (result == null) {
			result = StringDataType.dataType;
		}
		return result;
	}

	@Override
	public String toString() {
		return getStringValue();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	public static class StaticStringInstance extends StringDataInstance {
		private final String fakeStr;
		private final int fakeLen;

		public StaticStringInstance(String fakeStr, int fakeLen) {
			this.fakeStr = fakeStr;
			this.fakeLen = fakeLen;
		}

		@Override
		public String getStringValue() {
			return fakeStr;
		}

		@Override
		public String getStringRepresentation() {
			return fakeStr;
		}

		@Override
		public int getStringLength() {
			return fakeLen;
		}

		@Override
		public String getLabel(String prefixStr, String abbrevPrefixStr, String defaultStr,
				DataTypeDisplayOptions options) {
			return defaultStr;
		}

		@Override
		public String getOffcutLabelString(String prefixStr, String abbrevPrefixStr,
				String defaultStr, DataTypeDisplayOptions options, int offcutOffset) {
			return defaultStr;
		}
	}

	//--------------------------------------------------------------------------------------

	/**
	 * Simple class to hold tuple of (detected_charset_name,bom_bytes_to_skip,detected_endianness).
	 */
	private static class AdjustedCharsetInfo {
		String charsetName;
		int byteStartOffset;
		Endian endian;

		public AdjustedCharsetInfo(String charsetName) {
			this.charsetName = charsetName;
		}
	}

}
