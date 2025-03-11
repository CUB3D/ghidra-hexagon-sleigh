package hexagon;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.pcodeInject.InjectPayloadJava;
import ghidra.app.util.pcodeInject.PcodeOpEmitter;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectLdc extends InjectPayloadJava {

	public int mode;
	
	public static long bad;
	
	
	
	
	
	public InjectLdc(String sourceName, SleighLanguage language, long uniqBase, int mode) {
		super(sourceName, language, uniqBase);
		this.mode = mode;
		System.out.println("HexagonHandler::ctor");
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		System.out.println("HexagonHandler::pcode");
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, uniqueBase);
		
		if(mode == 0) {
			System.out.println("VN="+con.inputlist.get(0).encodePiece());
			InjectLdc.bad = con.inputlist.get(0).getOffset();
			
			pCode.emitVoidPcodeOpCall("_stub");
			return pCode.getPcodeOps();
		} else if(mode == 1) {
			System.out.println("bad="+Long.toString(InjectLdc.bad, 16)+", a="+con.baseAddr);

			if(InjectLdc.bad != 0) {
				Varnode c = new Varnode(language.getAddressFactory().getConstantSpace().getAddress(InjectLdc.bad), 4);
				return new PcodeOp[] {
						new PcodeOp(con.baseAddr, 0, PcodeOp.BRANCHIND, new Varnode[] { c} ),

				};
				
//			pCode.emitAssignConstantToRegister("branch_tgt", (int)
//					InjectLdc.bad);
//			pCode.emitIndirectCall("branch_tgt");
			}

//		List<PcodeOp> op = new ArrayList<>();
//		int seq = 0;
//		op.add(new PcodeOp(con.baseAddr, seq++, PcodeOp.CALLOTHER))
//		
//		PcodeOp[] res = new PcodeOp[op.size()];
//		op.toArray(res);
//		return res;
		
		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
		return pCode.getPcodeOps();
		}
		
		return null;
	}
}