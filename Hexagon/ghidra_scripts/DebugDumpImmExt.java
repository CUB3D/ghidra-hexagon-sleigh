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
// Attempt to parse single instruction from memory bytes at current location.
// Parse trace output written to Tool Console.
// @category sleigh
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.util.StringUtilities;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.Address;
import java.util.List;
import java.util.HashMap;
import java.util.Map;


public class DebugDumpImmExt extends GhidraScript {

	@Override
	public void run() throws Exception {

		
		if (currentProgram == null || currentAddress == null) {
								println("CA | CP = nul");
			return;
		}

		Map<String, Long> stats = new HashMap<>();
		Map<String, String> stats2 = new HashMap<>();

		AddressSetView set = currentSelection;
		if (set == null || set.isEmpty()) {
								println("Use whole program");
			set = currentProgram.getMemory().getExecuteSet();
		} else {
								println("Use selection");
}

		AddressIterator ai = set.getAddresses(true);
//int ii = 0;
		while(ai.hasNext()) {
								//System.out.println(ai);

			try {
				Address a = ai.next();
				if(a.getOffset() % 4 != 0) continue;
				SleighDebugLogger logger = new SleighDebugLogger(currentProgram, a, SleighDebugMode.VERBOSE);

				if (!logger.parseFailed()) {

					
					List<String> s = logger.getConstructorLineNumbers();
					boolean marker = false;
					boolean marker1 = false;
					boolean marker2 = false;
					int marker2start = 0;

				
					for (int i = 0; i < s.size(); i++) {
						if(!marker && s.get(i).contains("missing_marker0")) {
							marker = true;
						}
						if(marker && s.get(i).contains("missing_marker1")) {
							marker1 = true;
							break;
						}
					}
					if(marker) {
						for (int i = 0; i < s.size(); i++) {
							if(s.get(i).contains("immext_marker")) {
								marker2 = true;
								continue;
							}
							if(marker2 && s.get(i).contains("slot(")) {
								Long l = stats.getOrDefault(s.get(i), new Long(0));
								stats.put(s.get(i), l + 1);
								stats2.put(s.get(i), a.toString());
								marker2start = i;

								//println(s.get(i));
								break;
							}
						}
					}
					if(marker1) {
						marker2 = false;
						for (int i = marker2start; i < s.size(); i++) {
							if(s.get(i).contains("immext_marker")) {
								marker2 = true;
								continue;
							}
							if(marker2 && s.get(i).contains("slot(")) {
								Long l = stats.getOrDefault(s.get(i), new Long(0));
								stats.put(s.get(i), l + 1);
								stats2.put(s.get(i), a.toString());
								marker2start = i;

								//println(s.get(i));
								break;
							}
						}
					}
				}

			
//				println(logger.toString());
				//if(ii > 30000 && false) {			
				//	break;
				//}
				//ii += 1;
			} catch (Exception e) {
				println(e.getMessage());
			}
		}
		
		for(String i : stats.keySet()) {
			println(i + " : " + stats.get(i) + " - " + stats2.get(i));
		}

	}
	
}
