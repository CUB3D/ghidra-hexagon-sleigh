package hexagon;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.pcodeInject.InjectPayloadJava;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectLdc extends InjectPayloadJava {

	public int mode;
	
	public static long bad;
	public static Varnode badreg;
	public static long kind;
	
	
	
	//TODO: for this to work properly we likely have to lift entire conditionals
	
	public InjectLdc(String sourceName, SleighLanguage language, long uniqBase, int mode) {
		super(sourceName, language, uniqBase);
		this.mode = mode;
		System.out.println("HexagonHandler::ctor");
	}
	
	private Varnode convertRegisterToVarnode(Register reg) {
		Varnode vn = new Varnode(reg.getAddress(), reg.getBitLength() / 8);
		return vn;
	}


	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		System.out.println("HexagonHandler::pcode");
//		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, uniqueBase);
		
		// set the branch target
		if(mode == 0) {
			System.out.println("VN="+con.inputlist.get(0).encodePiece());
			
			Varnode input0 = con.inputlist.get(0);
			
			// If this is a register, ignore it, we only handle constant jumps
			if(input0.isConstant()) {
				InjectLdc.bad = input0.getOffset();
				InjectLdc.badreg = null;
				InjectLdc.kind = 0;
			} else if (input0.isRegister()) {
				InjectLdc.bad = 0;
				InjectLdc.badreg = input0;
				InjectLdc.kind = 1;
			}
			
			Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
			
			return new PcodeOp[] {
					new PcodeOp(con.baseAddr, 0, PcodeOp.COPY, new Varnode[] { x0,}, x0),

			};
			
			
			// do the branch
		} else if(mode == 1) {
			System.out.println("bad="+Long.toString(InjectLdc.bad, 16)+", a="+con.baseAddr);

			// constant mode
			if(InjectLdc.kind == 0) {
				// do we have a target set
			
				if(InjectLdc.bad != 0) {
					Address addr = con.nextAddr.getAddressSpace().getAddress(InjectLdc.bad);
					if(!program.getMemory().contains(addr)) {
						Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
						
						return new PcodeOp[] {
								new PcodeOp(con.baseAddr, 0, PcodeOp.COPY, new Varnode[] { x0,}, x0),
			
						};
					}
					try {
					new PseudoDisassembler(program).disassemble(addr);
					}catch(Exception e) {
						e.printStackTrace();
						Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
						
						return new PcodeOp[] {
								new PcodeOp(con.baseAddr, 0, PcodeOp.COPY, new Varnode[] { x0,}, x0),
			
						};
					}
					
					
					Varnode c = new Varnode(addr, 4);
					System.out.println(c.toString());
					System.out.println(con.baseAddr.toString());
					System.out.println(con.baseAddr.getAddressSpace().toString());
					return new PcodeOp[] {
							//TODO: branch
							new PcodeOp(con.baseAddr, 0, PcodeOp.BRANCH, new Varnode[] { c} ),
	
					};
					
				} else {	
					// No branch target was set, this one just falls through, do nothing
					Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
					
					return new PcodeOp[] {
							new PcodeOp(con.baseAddr, 0, PcodeOp.COPY, new Varnode[] { x0,}, x0),
		
					};
				}
			} else if (InjectLdc.kind == 1 && InjectLdc.badreg != null) {
//				return new PcodeOp[] {
//						new PcodeOp(con.baseAddr, 0, PcodeOp.BRANCHIND, new Varnode[] { InjectLdc.badreg} ),
//
//				};
				Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
				
				return new PcodeOp[] {
						new PcodeOp(con.baseAddr, 0, PcodeOp.COPY, new Varnode[] { x0,}, x0),

				};
			}

			
			
//			System.out.println("Should not happend");
//		List<PcodeOp> op = new ArrayList<>();
//		int seq = 0;
//		op.add(new PcodeOp(con.baseAddr, seq++, PcodeOp.CALLOTHER))
//		
//		PcodeOp[] res = new PcodeOp[op.size()];
//		op.toArray(res);
//		return res;
		
//		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
//		pCode.emitVoidPcodeOpCall("_stub");
//		return pCode.getPcodeOps();
		}
		
		return null;
	}
}