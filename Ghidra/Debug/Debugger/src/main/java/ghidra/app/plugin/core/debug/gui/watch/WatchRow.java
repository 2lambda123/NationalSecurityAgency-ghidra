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
package ghidra.app.plugin.core.debug.gui.watch;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DebuggerStateEditingService;
import ghidra.app.services.DebuggerStateEditingService.StateEditor;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.options.SaveState;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeEncodeException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.*;

public class WatchRow {
	public static final int TRUNCATE_BYTES_LENGTH = 64;
	private static final String KEY_EXPRESSION = "expression";
	private static final String KEY_DATA_TYPE = "dataType";
	private static final String KEY_SETTINGS = "settings";

	private final DebuggerWatchesProvider provider;
	private Trace trace;
	private DebuggerCoordinates coordinates;
	private SleighLanguage language;
	private PcodeExecutor<Pair<byte[], TraceMemoryState>> executorWithState;
	private ReadDepsPcodeExecutor executorWithAddress;
	private PcodeExecutor<byte[]> asyncExecutor; // name is reminder to use asynchronously

	private String expression;
	private String typePath;
	private DataType dataType;
	private SettingsImpl settings = new SettingsImpl();
	private SavedSettings savedSettings = new SavedSettings(settings);

	private PcodeExpression compiled;
	private TraceMemoryState state;
	private Address address;
	private Symbol symbol;
	private AddressSetView reads;
	private byte[] value;
	private byte[] prevValue; // Value at previous coordinates
	private String valueString;
	private Object valueObj;
	private Throwable error = null;

	public WatchRow(DebuggerWatchesProvider provider, String expression) {
		this.provider = provider;
		this.expression = expression;
	}

	protected void blank() {
		state = null;
		address = null;
		symbol = null;
		reads = null;
		value = null;
		valueString = null;
		valueObj = null;
	}

	protected void recompile() {
		compiled = null;
		error = null;
		if (expression == null || expression.length() == 0) {
			return;
		}
		if (language == null) {
			return;
		}
		try {
			compiled = SleighProgramCompiler.compileExpression(language, expression);
		}
		catch (Exception e) {
			error = e;
			return;
		}
	}

	protected void doTargetReads() {
		if (compiled != null && asyncExecutor != null) {
			CompletableFuture<byte[]> asyncEvaluation =
				CompletableFuture.supplyAsync(() -> compiled.evaluate(asyncExecutor));
			asyncEvaluation.exceptionally(ex -> {
				error = ex;
				Swing.runIfSwingOrRunLater(() -> {
					provider.watchTableModel.notifyUpdated(this);
				});
				return null;
			});
			// NB. Re-evaluation triggered by database changes, or called separately
		}
	}

	protected void reevaluate() {
		blank();
		if (trace == null || compiled == null) {
			return;
		}
		try {
			Pair<byte[], TraceMemoryState> valueWithState = compiled.evaluate(executorWithState);
			Pair<byte[], Address> valueWithAddress = compiled.evaluate(executorWithAddress);

			TracePlatform platform = provider.current.getPlatform();
			value = valueWithState.getLeft();
			error = null;
			state = valueWithState.getRight();
			// TODO: Optional column for guest address?
			address = platform.mapGuestToHost(valueWithAddress.getRight());
			symbol = computeSymbol();
			reads = platform.mapGuestToHost(executorWithAddress.getReads());

			valueObj = parseAsDataTypeObj();
			valueString = parseAsDataTypeStr();
		}
		catch (Exception e) {
			error = e;
		}
	}

	protected String parseAsDataTypeStr() {
		if (dataType == null || value == null) {
			return "";
		}
		MemBuffer buffer = new ByteMemBufferImpl(address, value, language.isBigEndian());
		return dataType.getRepresentation(buffer, settings, value.length);
	}

	// TODO: DataType settings

	protected Object parseAsDataTypeObj() {
		if (dataType == null || value == null) {
			return null;
		}
		MemBuffer buffer = new ByteMemBufferImpl(address, value, language.isBigEndian());
		return dataType.getValue(buffer, SettingsImpl.NO_SETTINGS, value.length);
	}

	public static class ReadDepsTraceBytesPcodeExecutorStatePiece
			extends DirectBytesTracePcodeExecutorStatePiece {
		private AddressSet reads = new AddressSet();

		public ReadDepsTraceBytesPcodeExecutorStatePiece(TracePlatform platform, long snap,
				TraceThread thread, int frame) {
			super(DirectBytesTracePcodeExecutorState.getDefaultThreadAccess(platform, snap, thread,
				frame));
		}

		@Override
		public byte[] getVar(AddressSpace space, long offset, int size, boolean quantize,
				Reason reason) {
			byte[] data = super.getVar(space, offset, size, quantize, reason);
			if (space.isMemorySpace()) {
				offset = quantizeOffset(space, offset);
			}
			if (space.isMemorySpace() || space.isRegisterSpace()) {
				try {
					reads.add(new AddressRangeImpl(space.getAddress(offset), data.length));
				}
				catch (AddressOverflowException | AddressOutOfBoundsException e) {
					throw new AssertionError(e);
				}
			}
			return data;
		}

		@Override
		protected void setInSpace(AddressSpace space, long offset, int size, byte[] val) {
			throw new UnsupportedOperationException("Expression cannot write to trace");
		}

		public void reset() {
			reads = new AddressSet();
		}

		public AddressSet getReads() {
			return new AddressSet(reads);
		}
	}

	public static class ReadDepsPcodeExecutor
			extends PcodeExecutor<Pair<byte[], Address>> {
		private ReadDepsTraceBytesPcodeExecutorStatePiece depsPiece;

		public ReadDepsPcodeExecutor(ReadDepsTraceBytesPcodeExecutorStatePiece depsState,
				SleighLanguage language, PairedPcodeArithmetic<byte[], Address> arithmetic,
				PcodeExecutorState<Pair<byte[], Address>> state) {
			super(language, arithmetic, state, Reason.INSPECT);
			this.depsPiece = depsState;
		}

		@Override
		public PcodeFrame execute(PcodeProgram program,
				PcodeUseropLibrary<Pair<byte[], Address>> library) {
			depsPiece.reset();
			return super.execute(program, library);
		}

		public AddressSet getReads() {
			return depsPiece.getReads();
		}
	}

	/**
	 * Build an executor that can compute three things simultaneously
	 * 
	 * <p>
	 * This computes the concrete value, its address, and the set of physical addresses involved in
	 * the computation. The resulting pair gives the value and its address. To get the addresses
	 * involved, invoke {@link ReadDepsPcodeExecutor#getReads()} after evaluation.
	 * 
	 * @param coordinates the coordinates providing context for the evaluation
	 * @return an executor for evaluating the watch
	 */
	protected static ReadDepsPcodeExecutor buildAddressDepsExecutor(
			DebuggerCoordinates coordinates) {
		TracePlatform platform = coordinates.getPlatform();
		ReadDepsTraceBytesPcodeExecutorStatePiece piece =
			new ReadDepsTraceBytesPcodeExecutorStatePiece(platform, coordinates.getViewSnap(),
				coordinates.getThread(), coordinates.getFrame());
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage slang)) {
			throw new IllegalArgumentException("Watch expressions require a Sleigh language");
		}
		PcodeExecutorState<Pair<byte[], Address>> paired = new DefaultPcodeExecutorState<>(piece)
				.paired(new AddressOfPcodeExecutorStatePiece(language));
		PairedPcodeArithmetic<byte[], Address> arithmetic = new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language), AddressOfPcodeArithmetic.INSTANCE);
		return new ReadDepsPcodeExecutor(piece, slang, arithmetic, paired);
	}

	public void setCoordinates(DebuggerCoordinates coordinates) {
		// NB. Caller has already verified coordinates actually changed
		prevValue = value;
		trace = coordinates.getTrace();
		this.coordinates = coordinates;
		updateType();
		if (trace == null) {
			blank();
			return;
		}
		Language newLanguage = trace.getBaseLanguage();
		if (language != newLanguage) {
			if (!(newLanguage instanceof SleighLanguage)) {
				error = new RuntimeException("Not a sleigh-based language");
				return;
			}
			language = (SleighLanguage) newLanguage;
			recompile();
		}
		if (coordinates.isAliveAndReadsPresent()) {
			asyncExecutor =
				DebuggerPcodeUtils.executorForCoordinates(provider.getTool(), coordinates);
		}
		executorWithState = TraceSleighUtils.buildByteWithStateExecutor(trace,
			coordinates.getViewSnap(), coordinates.getThread(), coordinates.getFrame());
		executorWithAddress = buildAddressDepsExecutor(coordinates);
	}

	public void setExpression(String expression) {
		if (!Objects.equals(this.expression, expression)) {
			prevValue = null;
			// NB. Allow fall-through so user can re-evaluate via nop edit.
		}
		this.expression = expression;
		blank();
		recompile();
		if (error != null) {
			provider.contextChanged();
			return;
		}
		if (asyncExecutor != null) {
			doTargetReads();
		}
		reevaluate();
		provider.contextChanged();
	}

	public String getExpression() {
		return expression;
	}

	protected void updateType() {
		dataType = null;
		if (typePath == null) {
			return;
		}
		// Try from the trace first
		if (trace != null) {
			dataType = trace.getDataTypeManager().getDataType(typePath);
			if (dataType != null) {
				return;
			}
		}
		// Either we have no trace, or the trace doesn't have the type.
		// Try built-ins
		DataTypeManagerService dtms = provider.getTool().getService(DataTypeManagerService.class);
		if (dtms != null) {
			dataType = dtms.getBuiltInDataTypesManager().getDataType(typePath);
		}
		// We're out of things to try, let null be null
	}

	public void setTypePath(String typePath) {
		this.typePath = typePath;
		updateType();
	}

	public String getTypePath() {
		return typePath;
	}

	public void setDataType(DataType dataType) {
		this.typePath = dataType == null ? null : dataType.getPathName();
		this.dataType = dataType;
		valueString = parseAsDataTypeStr();
		valueObj = parseAsDataTypeObj();
		provider.contextChanged();
		settings.setDefaultSettings(dataType == null ? null : dataType.getDefaultSettings());
		if (dataType != null) {
			savedSettings.read(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
	}

	public DataType getDataType() {
		return dataType;
	}

	/**
	 * Get the row's (mutable) data type settings
	 * 
	 * <p>
	 * After mutating these settings, the client must call {@link #settingsChanged()} to update the
	 * row's display and save state.
	 * 
	 * @return the settings
	 */
	public Settings getSettings() {
		return settings;
	}

	public void settingsChanged() {
		if (dataType != null) {
			savedSettings.write(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
		valueString = parseAsDataTypeStr();
		provider.watchTableModel.fireTableDataChanged();
	}

	public Address getAddress() {
		return address;
	}

	public AddressRange getRange() {
		if (address == null || value == null) {
			return null;
		}
		if (address.isConstantAddress()) {
			return new AddressRangeImpl(address, address);
		}
		try {
			return new AddressRangeImpl(address, value.length);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	public String getRawValueString() {
		if (value == null) {
			return "??";
		}
		if (address == null || !address.getAddressSpace().isMemorySpace()) {
			BigInteger asBigInt =
				Utils.bytesToBigInteger(value, value.length, language.isBigEndian(), false);
			return "0x" + asBigInt.toString(16);
		}
		if (value.length > TRUNCATE_BYTES_LENGTH) {
			// TODO: I'd like this not to affect the actual value, just the display
			//   esp., since this will be the "value" when starting to edit.
			return "{ " +
				NumericUtilities.convertBytesToString(value, 0, TRUNCATE_BYTES_LENGTH, " ") +
				" ... }";
		}
		return "{ " + NumericUtilities.convertBytesToString(value, " ") + " }";
	}

	/**
	 * Get the memory read by the watch, from the host platform perspective
	 * 
	 * @return the reads
	 */
	public AddressSetView getReads() {
		return reads;
	}

	public TraceMemoryState getState() {
		return state;
	}

	public String getValueString() {
		return valueString;
	}

	public Object getValueObj() {
		return valueObj;
	}

	public boolean isRawValueEditable() {
		if (!provider.isEditsEnabled()) {
			return false;
		}
		if (address == null) {
			return false;
		}
		DebuggerStateEditingService editingService = provider.editingService;
		if (editingService == null) {
			return false;
		}
		StateEditor editor = editingService.createStateEditor(coordinates);
		return editor.isVariableEditable(address, getValueLength());
	}

	public void setRawValueString(String valueString) {
		valueString = valueString.trim();
		if (valueString.startsWith("{")) {
			if (!valueString.endsWith("}")) {
				throw new NumberFormatException("Byte array values must be hex enclosed in {}");
			}

			setRawValueBytesString(valueString.substring(1, valueString.length() - 1));
			return;
		}

		setRawValueIntString(valueString);
	}

	public void setRawValueBytesString(String bytesString) {
		setRawValueBytes(NumericUtilities.convertStringToBytes(bytesString));
	}

	public void setRawValueIntString(String intString) {
		intString = intString.trim();
		final BigInteger val;
		if (intString.startsWith("0x")) {
			val = new BigInteger(intString.substring(2), 16);
		}
		else {
			val = new BigInteger(intString, 10);
		}
		setRawValueBytes(
			Utils.bigIntegerToBytes(val, value.length, trace.getBaseLanguage().isBigEndian()));
	}

	public void setRawValueBytes(byte[] bytes) {
		if (address == null) {
			throw new IllegalStateException("Cannot write to watch variable without an address");
		}
		if (bytes.length > value.length) {
			throw new IllegalArgumentException("Byte arrays cannot exceed length of variable");
		}
		if (bytes.length < value.length) {
			byte[] fillOld = Arrays.copyOf(value, value.length);
			System.arraycopy(bytes, 0, fillOld, 0, bytes.length);
			bytes = fillOld;
		}
		DebuggerStateEditingService editingService = provider.editingService;
		if (editingService == null) {
			throw new AssertionError("No editing service");
		}
		StateEditor editor = editingService.createStateEditor(coordinates);
		editor.setVariable(address, bytes).exceptionally(ex -> {
			Msg.showError(this, null, "Write Failed",
				"Could not modify watch value (on target)", ex);
			return null;
		});
	}

	public void setValueString(String valueString) {
		if (dataType == null || value == null) {
			// isValueEditable should have been false
			provider.getTool().setStatusInfo("Watch no value or no data type", true);
			return;
		}
		try {
			byte[] encoded = dataType.encodeRepresentation(valueString,
				new ByteMemBufferImpl(address, value, language.isBigEndian()),
				SettingsImpl.NO_SETTINGS, value.length);
			setRawValueBytes(encoded);
		}
		catch (DataTypeEncodeException e) {
			provider.getTool().setStatusInfo(e.getMessage(), true);
		}
	}

	public boolean isValueEditable() {
		if (!isRawValueEditable()) {
			return false;
		}
		if (dataType == null) {
			return false;
		}
		return dataType.isEncodable();
	}

	public int getValueLength() {
		return value == null ? 0 : value.length;
	}

	protected Symbol computeSymbol() {
		if (address == null || !address.isMemoryAddress()) {
			return null;
		}
		Collection<? extends TraceLabelSymbol> labels =
			trace.getSymbolManager().labels().getAt(coordinates.getSnap(), null, address, false);
		if (!labels.isEmpty()) {
			return labels.iterator().next();
		}
		// TODO: Check trace functions? They don't work yet.
		if (provider.mappingService == null) {
			return null;
		}
		TraceLocation dloc =
			new DefaultTraceLocation(trace, null, Range.singleton(coordinates.getSnap()), address);
		ProgramLocation sloc = provider.mappingService.getOpenMappedLocation(dloc);
		if (sloc == null) {
			return null;
		}

		Program program = sloc.getProgram();
		SymbolTable table = program.getSymbolTable();
		Symbol primary = table.getPrimarySymbol(address);
		if (primary != null) {
			return primary;
		}
		SymbolIterator sit = table.getSymbolsAsIterator(sloc.getByteAddress());
		if (sit.hasNext()) {
			return sit.next();
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			return function.getSymbol();
		}
		return null;
	}

	public Symbol getSymbol() {
		return symbol;
	}

	public String getErrorMessage() {
		if (error == null) {
			return "";
		}
		String message = error.getMessage();
		if (message != null && message.trim().length() != 0) {
			return message;
		}
		return error.getClass().getSimpleName();
	}

	public Throwable getError() {
		return error;
	}

	public boolean isKnown() {
		return state == TraceMemoryState.KNOWN;
	}

	public boolean isChanged() {
		if (prevValue == null) {
			return false;
		}
		return !Arrays.equals(value, prevValue);
	}

	protected void writeConfigState(SaveState saveState) {
		saveState.putString(KEY_EXPRESSION, expression);
		saveState.putString(KEY_DATA_TYPE, typePath);
		saveState.putSaveState(KEY_SETTINGS, savedSettings.getState());
	}

	protected void readConfigState(SaveState saveState) {
		setExpression(saveState.getString(KEY_EXPRESSION, ""));
		setTypePath(saveState.getString(KEY_DATA_TYPE, null));

		savedSettings.setState(saveState.getSaveState(KEY_SETTINGS));
		if (dataType != null) {
			savedSettings.read(dataType.getSettingsDefinitions(), dataType.getDefaultSettings());
		}
	}
}
