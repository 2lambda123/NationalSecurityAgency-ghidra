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
package ghidra.app.plugin.core.memory;

import java.awt.Cursor;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.JTable;
import javax.swing.table.TableCellEditor;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.table.ProgramTableModel;

/**
 * Table Model for a Table where each entry represents a MemoryBlock from a Program's Memory.
 */
class MemoryMapModel extends AbstractSortedTableModel<MemoryBlock> implements ProgramTableModel {

	final static byte NAME = 0;
	final static byte START = 1;
	final static byte END = 2;
	final static byte LENGTH = 3;
	final static byte READ = 4;
	final static byte WRITE = 5;
	final static byte EXECUTE = 6;
	final static byte VOLATILE = 7;
	final static byte ARTIFICIAL = 8;
	final static byte OVERLAY = 9;
	final static byte BLOCK_TYPE = 10;
	final static byte INIT = 11;
	final static byte BYTE_SOURCE = 12;
	final static byte SOURCE = 13;
	final static byte COMMENT = 14;

	final static String NAME_COL = "Name";
	final static String START_COL = "Start";
	final static String END_COL = "End";
	final static String LENGTH_COL = "Length";
	final static String READ_COL = "R";
	final static String WRITE_COL = "W";
	final static String EXECUTE_COL = "X";
	final static String VOLATILE_COL = "Volatile";
	final static String ARTIFICIAL_COL = "Artificial";
	final static String OVERLAY_COL = "Overlayed Space";
	final static String BLOCK_TYPE_COL = "Type";
	final static String INIT_COL = "Initialized";
	final static String BYTE_SOURCE_COL = "Byte Source";
	final static String SOURCE_COL = "Source";
	final static String COMMENT_COL = "Comment";

	private final static Cursor WAIT_CURSOR = Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR);
	private final static Cursor DEFAULT_CURSOR = Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR);

	private Program program;
	private List<MemoryBlock> memList;
	private MemoryMapProvider provider;

	private final static String COLUMN_NAMES[] = { NAME_COL, START_COL, END_COL, LENGTH_COL,
		READ_COL, WRITE_COL, EXECUTE_COL, VOLATILE_COL, ARTIFICIAL_COL, OVERLAY_COL, BLOCK_TYPE_COL,
		INIT_COL, BYTE_SOURCE_COL, SOURCE_COL, COMMENT_COL };

	MemoryMapModel(MemoryMapProvider provider, Program program) {
		super(START);
		this.provider = provider;
		setProgram(program);
	}

	void setProgram(Program program) {
		this.program = program;
		populateMap();
	}

	private void populateMap() {
		memList = new ArrayList<>();

		if (program == null) {
			fireTableDataChanged();
			return;
		}

		// Get all the memory blocks
		Memory mem = program.getMemory();
		MemoryBlock[] blocks = mem.getBlocks();
		for (MemoryBlock block : blocks) {
			memList.add(block);
		}
		fireTableDataChanged();
	}

	void update() {
		JTable table = provider.getTable();
		TableCellEditor cellEditor = table.getCellEditor();
		if (cellEditor != null) {
			cellEditor.cancelCellEditing();
		}
		populateMap();
	}

	@Override
	public boolean isSortable(int columnIndex) {
		if (columnIndex == READ || columnIndex == WRITE || columnIndex == EXECUTE ||
			columnIndex == VOLATILE || columnIndex == ARTIFICIAL || columnIndex == INIT) {
			return false;
		}
		return true;
	}

	@Override
	public String getName() {
		return "Memory Map";
	}

	@Override
	public int getColumnCount() {
		return COLUMN_NAMES.length;
	}

	@Override
	public String getColumnName(int column) {

		if (column < 0 || column >= COLUMN_NAMES.length) {
			return "UNKNOWN";
		}

		return COLUMN_NAMES[column];
	}

	@Override
	public int findColumn(String columnName) {
		for (int i = 0; i < COLUMN_NAMES.length; i++) {
			if (COLUMN_NAMES[i].equals(columnName)) {
				return i;
			}
		}
		return 0;
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == READ || columnIndex == WRITE || columnIndex == EXECUTE ||
			columnIndex == VOLATILE || columnIndex == ARTIFICIAL || columnIndex == INIT) {
			return Boolean.class;
		}
		return String.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {

		switch (columnIndex) {
			case NAME:
			case READ:
			case WRITE:
			case EXECUTE:
			case VOLATILE:
			case ARTIFICIAL:
				return true;
			case COMMENT:
				return true;
			case INIT:
				MemoryBlock block = memList.get(rowIndex);
				MemoryBlockType blockType = block.getType();
				if (blockType != MemoryBlockType.BIT_MAPPED &&
					blockType != MemoryBlockType.BYTE_MAPPED) {
					return true;
				}
			default:
				return false;
		}
	}

	@Override
	public int getRowCount() {
		return memList.size();
	}

	private String getAddressString(Address address) {
		return address.toString();
	}

	public MemoryBlock getBlockAt(int rowIndex) {
		if (memList == null) {
			return null;
		}
		if (rowIndex < 0 || rowIndex >= memList.size()) {
			return null;
		}
		return memList.get(rowIndex);
	}

	@Override
	public void setValueAt(Object aValue, int row, int column) {
		provider.setCursor(WAIT_CURSOR);
		try {

			MemoryBlock block = getBlockAt(row);
			if (block == null) {
				// this can happen when the tool is closing while an edit is open
				return;
			}

			doSetValueAt(aValue, row, column, block);
		}
		finally {
			provider.setCursor(DEFAULT_CURSOR);
		}
	}

	private void doSetValueAt(Object aValue, int row, int column, MemoryBlock block) {

		switch (column) {
			case NAME:
				setName(block, (String) aValue);
				break;
			case READ: {
				program.withTransaction("Set Read State", () -> {
					boolean value = ((Boolean) aValue).booleanValue();
					block.setRead(value);
					provider.setStatusText("");
				});
				break;
			}
			case WRITE: {
				program.withTransaction("Set Write State", () -> {
					boolean value = ((Boolean) aValue).booleanValue();
					block.setWrite(value);
					provider.setStatusText("");
				});
				break;
			}
			case EXECUTE: {
				program.withTransaction("Set Execute State", () -> {
					boolean value = ((Boolean) aValue).booleanValue();
					block.setExecute(value);
					provider.setStatusText("");
				});
				break;
			}
			case VOLATILE: {
				program.withTransaction("Set Volatile State", () -> {
					boolean value = ((Boolean) aValue).booleanValue();
					block.setVolatile(value);
					provider.setStatusText("");
				});
				break;
			}
			case ARTIFICIAL: {
				program.withTransaction("Set Artificial State", () -> {
					boolean value = ((Boolean) aValue).booleanValue();
					block.setArtificial(value);
					provider.setStatusText("");
				});
				break;
			}
			case INIT:
				MemoryBlockType blockType = block.getType();
				if (blockType == MemoryBlockType.BIT_MAPPED ||
					blockType == MemoryBlockType.BYTE_MAPPED) {
					showMessage("Cannot change intialized memory state of a mapped Block");
					break;
				}
				provider.setStatusText("");
				boolean booleanValue = ((Boolean) aValue).booleanValue();
				if (booleanValue) {
					initializeBlock(block);
				}
				else {
					revertBlockToUninitialized(block);
				}
				break;
			case SOURCE:
				break;
			case COMMENT:
				setComment(block, (String) aValue);
				break;
			default:
				break;
		}
		fireTableRowsUpdated(row, column);
	}

	private void setComment(MemoryBlock block, String aValue) {

		String cmt = block.getComment();
		if (cmt == null || !cmt.equals(aValue)) {
			if (aValue.length() == 0) {
				aValue = null;
			}

			String newValue = aValue;
			program.withTransaction("Set Comment", () -> {
				block.setComment(newValue);
			});
		}
	}

	private void setName(MemoryBlock block, String name) {
		name = name.trim();
		if (!verifyRenameAllowed(block, name)) {
			return;
		}
		if (name.length() == 0) {
			Msg.showError(this, provider.getComponent(), "Enter Block Label",
				"Please enter a label name.");
			return;
		}
		if (name.equals(block.getName())) {
			return;
		}
		if (!Memory.isValidMemoryBlockName(name)) {
			Msg.showError(this, provider.getComponent(), "Invalid Name",
				"Invalid Memory Block Name: " + name);
			return;
		}

		try {
			String newName = name;
			program.withTransaction("Rename Memory Block", () -> {
				block.setName(newName);
			});
		}
		catch (LockException e) {
			this.provider.setStatusText(e.getMessage());
		}
	}

	private void revertBlockToUninitialized(MemoryBlock block) {
		int result = OptionDialog.showYesNoDialog(provider.getComponent(),
			"Confirm Setting Block To Uninitialized",
			"Are you sure you want to remove the bytes from this block? \n\n" +
				"This will result in removing all functions, instructions, data,\n" +
				"and outgoing references from the block!");

		if (result == OptionDialog.NO_OPTION) {
			return;
		}
		UninitializedBlockCmd cmd = new UninitializedBlockCmd(block);
		provider.getTool().executeBackgroundCommand(cmd, program);
	}

	private boolean verifyRenameAllowed(MemoryBlock block, String newName) {
		if (!block.isOverlay() || block.getName().equals(newName)) {
			return true;
		}
		if (!program.hasExclusiveAccess()) {
			String msg = "Close the file and undo your checkout,\n" +
				"then do a checkout with the exclusive lock.";

			DomainFile df = program.getDomainFile();
			if (df.modifiedSinceCheckout() || df.isChanged()) {
				msg = "Check in this file, then do a checkout with the\n" + "exclusive lock.";
			}
			Msg.showInfo(getClass(), provider.getComponent(), "Exclusive Checkout Required",
				"An exclusive checkout is required in order to\n" +
					"rename an overlay memory block.\n" + msg);
			return false;
		}
		return true;
	}

	/**
	 * Create a new initialized block based on the given uninitialized block.
	 */
	private void initializeBlock(MemoryBlock block) {

		NumberInputDialog dialog = new NumberInputDialog("Initialize Memory Block",
			"Enter fill byte value for block: ", 0, 0, 255, true);

		if (!dialog.show()) {
			return;	// cancelled
		}

		byte value = (byte) dialog.getValue();

		int id = program.startTransaction("Initialize Memory Block");
		try {
			Memory mem = program.getMemory();
			int index = memList.indexOf(block);
			MemoryBlock newBlock = mem.convertToInitialized(block, value);
			memList.set(index, newBlock);
			program.endTransaction(id, true);
		}
		catch (Throwable t) {
			program.endTransaction(id, false);
			String msg = ExceptionUtils.getMessage(t);
			Msg.showError(this, provider.getComponent(), "Block Initialization Failed", msg, t);
		}
	}

	private void showMessage(String msg) {
		// mouse listeners wipe out the message so show it later...
		Swing.runLater(() -> provider.setStatusText(msg));
	}

	@Override
	public Object getColumnValueForRow(MemoryBlock block, int columnIndex) {
		try {
			switch (columnIndex) {
				case NAME:
					return block.getName();
				case START:
					return getAddressString(block.getStart());
				case END:
					return getAddressString(block.getEnd());
				case LENGTH:
					long len = block.getEnd().subtract(block.getStart()) + 1;
					return "0x" + Long.toHexString(len);
				case READ:
					return block.isRead() ? Boolean.TRUE : Boolean.FALSE;
				case WRITE:
					return block.isWrite() ? Boolean.TRUE : Boolean.FALSE;
				case EXECUTE:
					return block.isExecute() ? Boolean.TRUE : Boolean.FALSE;
				case VOLATILE:
					return block.isVolatile() ? Boolean.TRUE : Boolean.FALSE;
				case ARTIFICIAL:
					return block.isArtificial() ? Boolean.TRUE : Boolean.FALSE;
				case OVERLAY:
					return getOverlayBaseSpaceName(block);
				case INIT:
					MemoryBlockType blockType = block.getType();
					if (blockType == MemoryBlockType.BIT_MAPPED) {
						return null;
					}
					return (block.isInitialized() ? Boolean.TRUE : Boolean.FALSE);
				case BYTE_SOURCE:
					return getByteSourceDescription(block.getSourceInfos());
				case SOURCE:
					if ((block.getType() == MemoryBlockType.BIT_MAPPED) ||
						(block.getType() == MemoryBlockType.BYTE_MAPPED)) {
						MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
						return info.getMappedRange().get().getMinAddress().toString();
					}
					return block.getSourceName();
				case COMMENT:
					return block.getComment();
				case BLOCK_TYPE:
					return block.getType().toString();
				default:
					return "UNKNOWN";
			}
		}
		catch (ConcurrentModificationException e) {
			update();
		}
		return null;
	}

	private String getByteSourceDescription(List<MemoryBlockSourceInfo> sourceInfos) {
		List<MemoryBlockSourceInfo> limited =
			sourceInfos.size() < 5 ? sourceInfos : sourceInfos.subList(0, 4);

		//@formatter:off
		String description = limited
							.stream()
							.map(info -> info.getDescription())
							.collect(Collectors.joining(" | "));
		//@formatter:on
		if (limited != sourceInfos) {
			description += "...";
		}
		return description;
	}

	@Override
	public List<MemoryBlock> getModelData() {
		return memList;
	}

	@Override
	protected Comparator<MemoryBlock> createSortComparator(int columnIndex) {
		if (columnIndex == BYTE_SOURCE) {
			return super.createSortComparator(columnIndex);
		}
		return new MemoryMapComparator(columnIndex);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {

		MemoryBlock block = getRowObject(row);
		Address address = block.getStart();
		if (column == END) {
			address = block.getEnd();
		}

		return new ProgramLocation(program, address);
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {

		if (rows.length == 0) {
			return null;
		}

		AddressSet addressSet = new AddressSet();
		for (int row : rows) {

			MemoryBlock block = getRowObject(row);
			Address start = block.getStart();
			Address end = block.getEnd();

			if (start.isMemoryAddress() && end.isMemoryAddress()) {
				addressSet.addRange(start, end);
			}
		}
		return new ProgramSelection(addressSet);
	}

	@Override
	public Program getProgram() {
		return program;
	}

	private String getOverlayBaseSpaceName(MemoryBlock block) {
		AddressSpace space = block.getStart().getAddressSpace();
		if (space instanceof OverlayAddressSpace ovSpace) {
			return ovSpace.getOverlayedSpace().getName();
		}
		return "";
	}

	private class MemoryMapComparator implements Comparator<MemoryBlock> {
		private final int sortColumn;

		public MemoryMapComparator(int sortColumn) {
			this.sortColumn = sortColumn;
		}

		@Override
		public int compare(MemoryBlock b1, MemoryBlock b2) {

			switch (sortColumn) {
				case NAME:
					return b1.getName().compareToIgnoreCase(b2.getName());
				case START:
					return b1.getStart().compareTo(b2.getStart());
				case END:
					return b1.getEnd().compareTo(b2.getEnd());
				case LENGTH:
					return (int) (b1.getSize() - b2.getSize());
				case READ:
					return Boolean.compare(b1.isRead(), b2.isRead());
				case WRITE:
					return Boolean.compare(b1.isWrite(), b2.isWrite());
				case EXECUTE:
					return Boolean.compare(b1.isExecute(), b2.isExecute());
				case VOLATILE:
					return Boolean.compare(b1.isVolatile(), b2.isVolatile());
				case ARTIFICIAL:
					return Boolean.compare(b1.isArtificial(), b2.isArtificial());
				case OVERLAY:
					String ov1 = getOverlayBaseSpaceName(b1);
					String ov2 = getOverlayBaseSpaceName(b2);
					return ov1.compareTo(ov2);
				case INIT:
					return Boolean.compare(b1.isInitialized(), b2.isInitialized());

				//case BYTE_SOURCE: - handled by default comparator

				case SOURCE:
					String b1src = b1.getSourceName();
					String b2src = b2.getSourceName();
					if (b1src == null) {
						b1src = "";
					}
					if (b2src == null) {
						b2src = "";
					}
					return b1src.compareToIgnoreCase(b2src);

				case COMMENT:
					String comment1 = b1.getComment();
					String comment2 = b2.getComment();
					if (comment1 == null) {
						comment1 = "";
					}
					if (comment2 == null) {
						comment2 = "";
					}
					return comment1.compareToIgnoreCase(comment2);

				case BLOCK_TYPE:
					String bt1 = b1.getType().toString();
					String bt2 = b2.getType().toString();
					return bt1.compareToIgnoreCase(bt2);
				default:
					throw new RuntimeException("Unimplemented column comparator: " + sortColumn);
			}
		}
	}

}
