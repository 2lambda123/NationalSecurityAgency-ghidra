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
package pdb;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import ghidra.app.plugin.core.analysis.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.disassembler.EntryPointAnalyzer;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorControl;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class LoadPdbTask extends Task {
	private File pdbFile;
	private DataTypeManagerService service;
	private final Program program;
	private final boolean useMsDiaParser;
	private final PdbApplicatorControl control; // PDB Universal Parser only
	private String resultMessages;
	private Exception resultException;

	LoadPdbTask(Program program, File pdbFile, boolean useMsDiaParser, PdbApplicatorControl control,
			DataTypeManagerService service) {
		super("Load PDB", true, false, true, true);
		this.program = program;
		this.pdbFile = pdbFile;
		this.useMsDiaParser = useMsDiaParser;
		this.control = control;
		this.service = service;
	}

	@Override
	public void run(TaskMonitor monitor) {

		WrappingTaskMonitor wrappedMonitor = new WrappingTaskMonitor(monitor) {
			@Override
			public void initialize(long max) {
				// don't let called clients change our monitor type; we don't show progress
			}
		};

		MessageLog log = new MessageLog();
		AnalysisWorker worker = new AnalysisWorker() {

			@Override
			public String getWorkerName() {
				return "Load PDB";
			}

			@Override
			public boolean analysisWorkerCallback(Program currentProgram, Object workerContext,
					TaskMonitor currentMonitor) throws CancelledException {

				try {
					if (useMsDiaParser) {
						if (!parseWithMsDiaParser(log, wrappedMonitor)) {
							return false;
						}
					}
					else if (!parseWithNewParser(log, wrappedMonitor)) {
						return false;
					}
					scheduleAdditionalAnalysis();
				}
				catch (IOException e) {
					log.appendMsg("PDB IO Error: " + e.getMessage());
				}
				return false;
			}
		};

		try {
			AutoAnalysisManager.getAnalysisManager(program)
					.scheduleWorker(worker, null, true, wrappedMonitor);
		}
		catch (InterruptedException | CancelledException e) {
			// ignore
		}
		catch (InvocationTargetException e) {
			resultException = e;
		}
		if (log.hasMessages()) {
			resultMessages = log.toString();
		}

	}

	String getResultMessages() {
		return resultMessages;
	}

	Exception getResultException() {
		return resultException;
	}

	private boolean parseWithMsDiaParser(MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		PdbParser parser = new PdbParser(pdbFile, program, service, true, true, monitor);
		try {
			parser.parse();
			parser.openDataTypeArchives();
			parser.applyTo(log);
			return true;
		}
		catch (PdbException | DuplicateIdException e) {
			log.appendMsg("PDB Error: " + e.getMessage());
		}
		return false;
	}

	private boolean parseWithNewParser(MessageLog log, TaskMonitor monitor)
			throws CancelledException {

		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions(); // use defaults

		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();

		pdbApplicatorOptions.setProcessingControl(control);

		return PdbUniversalAnalyzer.doAnalysis(program, pdbFile, pdbReaderOptions,
			pdbApplicatorOptions, log, monitor);
	}

	// We need to kick off any byte analyzers (like getting import symbols), as they typically
	// won't get kicked off by our loading of the PDB.
	private void scheduleAdditionalAnalysis() {

		AddressSetView addrs = program.getMemory();
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		Options analysisProperties = program.getOptions(Program.ANALYSIS_PROPERTIES);

		if (!useMsDiaParser && control == PdbApplicatorControl.ALL) {
			// one-byte functions could have been laid down
			scheduleEntryPointAnalyzer(manager, analysisProperties, addrs);
		}
		if (useMsDiaParser || control != PdbApplicatorControl.DATA_TYPES_ONLY) {
			// mangled symbols could have been laid down
			scheduleDemanglerAnalyzer(manager, analysisProperties, addrs);
		}

	}

	private void scheduleEntryPointAnalyzer(AutoAnalysisManager manager, Options analysisProperties,
			AddressSetView addrs) {
		// Only schedule analyzer if enabled
		if (!analysisProperties.getBoolean(EntryPointAnalyzer.NAME, false)) {
			return;
		}
		EntryPointAnalyzer entryPointAnalyzer = new EntryPointAnalyzer();
		manager.scheduleOneTimeAnalysis(entryPointAnalyzer, addrs);
	}

	private void scheduleDemanglerAnalyzer(AutoAnalysisManager manager, Options analysisProperties,
			AddressSetView addrs) {
		// Only schedule analyzer if enabled
		if (!analysisProperties.getBoolean(MicrosoftDemanglerAnalyzer.NAME, false)) {
			return;
		}
		MicrosoftDemanglerAnalyzer demanglerAnalyzer = new MicrosoftDemanglerAnalyzer();
		manager.scheduleOneTimeAnalysis(demanglerAnalyzer, addrs);
	}

}
