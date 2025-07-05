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
package hexagon;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class HexagonAnalyzer extends AbstractAnalyzer {
	
	Register or1;
	Register or2;
	Register or3;
	Register analysed;

	Register[] regs_set = {or1, or2, or3};;
	
	public HexagonAnalyzer() {

		// Name the analyzer and give it a description.

		super("Hexagon dotnew Analyzer"
				+ "", "Analyzer description goes here", AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.
		
		or1 = program.getProgramContext().getRegister("or1test");
		or2 = program.getProgramContext().getRegister("or2test");
		or3 = program.getProgramContext().getRegister("or3test");
		analysed = program.getProgramContext().getRegister("analysed");

		regs_set[0] = or1;
		regs_set[1] = or2;
		regs_set[2] = or3;

		
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException{
		
		final long locationCount = set.getNumAddresses();
		monitor.initialize(locationCount);
		
		AddressIterator addresses = set.getAddresses(true);
		
		long count = 0;
		
		Listing list = program.getListing();
		
//		for(Register r : program.getProgramContext().getContextRegisters()) {
//
//			log.appendMsg("" + r);
//		}
		
		
		
//		log.appendMsg("" + or1);
//		log.appendMsg("" + or2);
//		log.appendMsg("" + or3);
		
		
//		
//		
	
		
		while (addresses.hasNext()) {
			monitor.checkCancelled();

			Address addr = addresses.next();
			
			BigInteger old_or1 = program.getProgramContext().getValue(analysed, addr, false);
			if(old_or1 != null) {
				if(old_or1.intValue() != 0) {
					continue;
				}
			}

			monitor.setProgress(count);
			count += 1;

			Instruction inst = list.getInstructionAt(addr);
			if (inst == null) {
				continue;
			}
			
			String ins = inst.toString();
			// rX | rXX | LR | FP | SP
			Pattern regs = Pattern.compile("(r\\d{1,2})|LR|FP|SP\\s*=");
			Matcher m = regs.matcher(ins);
//			log.appendMsg(ins);
//			System.out.println(ins);
			int idx = 0;
			List<Integer> outvals = new ArrayList<>();
			while(m.find()) {
				String g = m.group();
//				log.appendMsg(g);
//				System.out.println(g);
				g = g.replaceAll("=", "");
				g = g.strip();
				
				if(g.startsWith("r")) {
					String num = g.substring(1);
//					log.appendMsg(""+num);
//					System.out.println(""+num);
					int val = Integer.parseInt(num);
					val *= 4;
					log.appendMsg(""+val);
					System.out.println(""+val);
										
					outvals.add(val);
					idx += 1;
				}
			}
			
			program.getListing().clearCodeUnits(addr, addr.add(2), true);
			
			try {
				program.getProgramContext().setValue(analysed, addr, addr, new BigInteger("1"));
			} catch (ContextChangeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			

			for(int idx2 = 0; idx2 < idx; idx2++) {
				if(idx2 < 3) {
					int val = outvals.get(idx2);
					try {
						program.getProgramContext().setValue(regs_set[idx2], addr, addr, new BigInteger(""+val));
					} catch (ContextChangeException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
			
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSet disassembled = dis.disassemble(addr, null, false);
			if (!disassembled.contains(addr)) {
				// give up, the instruction couldn't be disassembled
				return false;
			}

			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);
		}

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		return true;
	}
}
