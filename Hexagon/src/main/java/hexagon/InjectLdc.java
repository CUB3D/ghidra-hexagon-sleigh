package hexagon;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.pcodeInject.InjectPayloadJava;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Handle all branches
 * 
 * This allows queueing branches as a packet is processed and generating the correct pcode at the end
 * the advantage of this is that we can generate non-indirect jumps that optimise better, if we use a fake register then it has to be fully indirect and the decompiler doesn't like that
 * also we can handle the odd cases like cond-jmp; call which should only take the call on the false case of the cond 
 */
public class InjectLdc extends InjectPayloadJava {

	public int mode;
	
	public static long bad;
	
	
	public static List<BranchImpl> branches = new ArrayList<>();
	

	public static final long CMP_EQ = 0;
	public static final long CMP_NEQ = 1;
	public static final long CMP_LTE = 2;
	
	abstract class BranchImpl {
		public abstract int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out);
	}
	
	class UncondCallImpl extends BranchImpl {
		public Varnode tgt;
		
		public UncondCallImpl(Varnode tgt, AddressSpace ram) {
			this.tgt = new Varnode(ram.getAddress(tgt.getOffset()), tgt.getSize());
		}

		@Override
		public int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out) {

			System.out.println(tgt.encodePiece());
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.CALL, new Varnode[] { tgt }));
			
			return slot;
		}
		
	}
	
	class UncondCallIndirectImpl extends BranchImpl {
		public Varnode tgt;
		
		public UncondCallIndirectImpl(Varnode tgt, AddressSpace ram) {
			this.tgt = tgt;
		}

		@Override
		public int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out) {

			System.out.println(tgt.encodePiece());
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.CALLIND, new Varnode[] { tgt }));
			
			return slot;
		}
		
	}
	
	class UncondJumpIndirectImpl extends BranchImpl {
		public Varnode tgt;
		
		public UncondJumpIndirectImpl(Varnode tgt, AddressSpace ram) {
			this.tgt = tgt;
		}

		@Override
		public int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out) {

			System.out.println(tgt.encodePiece());
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.BRANCHIND, new Varnode[] { tgt}));
			
			return slot;
		}
		
	}
	
	class UncondJumpAddressImpl extends BranchImpl {
		public Varnode tgt;
		
		public UncondJumpAddressImpl(Varnode tgt, AddressSpace ram) {
			this.tgt = new Varnode(ram.getAddress(tgt.getOffset()), tgt.getSize());
		}

		@Override
		public int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out) {

			System.out.println("Uncond jump: " + tgt.encodePiece());
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.BRANCH, new Varnode[] { tgt }));
			
			return slot;
		}
		
	}
	
	class CondJumpAddressImpl extends CondJumpIndirectImpl {
		public CondJumpAddressImpl(Varnode tgt, Varnode cmpa, Varnode cmpb, long cmpType, AddressSpace ram, AddressSpace unique) {
			super(tgt, cmpa, cmpb, cmpType, ram, unique);
			this.tgt = new Varnode(ram.getAddress(tgt.getOffset()), tgt.getSize());
		}
	}

	public static int convertCmpToPcodeOp(long cmpType) {
		if(cmpType == CMP_EQ) {
			return PcodeOp.INT_EQUAL;
		} else if(cmpType == CMP_NEQ) {
			return PcodeOp.INT_NOTEQUAL;
		}else if(cmpType == CMP_LTE) {
			return PcodeOp.INT_LESSEQUAL;
		}
		
		System.out.println("bad cmp type: " + cmpType);

		return PcodeOp.UNIMPLEMENTED;
	}
	
	class CondJumpIndirectImpl extends BranchImpl {
		public Varnode tgt;
		
		public Varnode outNode;
		public Varnode cmpa;
		public Varnode cmpb;
		public long cmpType;
		
		
		public CondJumpIndirectImpl(Varnode tgt, Varnode cmpa, Varnode cmpb, long cmpType, AddressSpace ram, AddressSpace unique) {
			this.tgt = tgt;
			this.outNode = new Varnode(unique.getAddress(0x100000), 4);
			this.cmpa = cmpa;
			this.cmpb = cmpb;
			this.cmpType = cmpType;
		}

		@Override
		public int getPcode(InjectContext con, int slot, ArrayList<PcodeOp> out) {

			System.out.println(tgt.encodePiece());			
			
			int cmpOp = convertCmpToPcodeOp(this.cmpType);
			
			out.add(new PcodeOp(con.baseAddr, slot++, cmpOp, new Varnode[] { this.cmpa, this.cmpb}, this.outNode));
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.CBRANCH, new Varnode[] { this.tgt, this.outNode}));
			
			return slot;
		}
	}
	
	
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
		//System.out.println("HexagonHandler::pcode");
		
		// set the branch target
		if(mode == 0) {
			
			AddressSpace unique = language.getAddressFactory().getUniqueSpace();
			AddressSpace ram  = con.nextAddr.getAddressSpace();
			
			System.out.println("adding ["+ con.inputlist.get(0).encodePiece() + ", " + con.inputlist.get(1).encodePiece() + "]");
			
			
			long input0 = con.inputlist.get(0).getOffset();
			Varnode input1 = con.inputlist.get(1);
			
			if (input0 == 0) {
				InjectLdc.branches.clear();
			} else if(input0 == 1) {
				InjectLdc.branches.add(new UncondCallImpl(input1, ram));
			} else if(input0 == 2) {
				InjectLdc.branches.add(new CondJumpAddressImpl(con.inputlist.get(4), input1, con.inputlist.get(3), con.inputlist.get(2).getOffset(), ram, unique));
			} else if(input0 == 3) {
				InjectLdc.branches.add(new UncondCallIndirectImpl(input1, ram));
			}else if(input0 == 4) {
				InjectLdc.branches.add(new UncondJumpIndirectImpl(input1, ram));
			}else if(input0 == 5) {
				InjectLdc.branches.add(new CondJumpIndirectImpl(con.inputlist.get(4), input1, con.inputlist.get(3), con.inputlist.get(2).getOffset(), ram, unique));
			}else if(input0 == 6) {
				InjectLdc.branches.add(new UncondJumpAddressImpl(input1, ram));
			}
			
			Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
			
			return new PcodeOp[] {
					new PcodeOp(con.baseAddr, 2000, PcodeOp.COPY, new Varnode[] { x0 }, x0),

			};
			
			
			// do the branch
		} else if(mode == 1) {
			System.out.println("bad="+Long.toString(InjectLdc.bad, 16)+", a="+con.baseAddr);
			
			
			System.out.println("generating ops");

			ArrayList<PcodeOp> out = new ArrayList<>();
			int slot = 1000;
			
			Varnode x0 = convertRegisterToVarnode(language.getRegister("X0"));
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.COPY, new Varnode[] { x0 }, x0));
			
			for(BranchImpl b : InjectLdc.branches) {
			//	slot = b.getPcode(con, slot, out);
			}
			
			out.add(new PcodeOp(con.baseAddr, slot++, PcodeOp.COPY, new Varnode[] { x0 }, x0));

			
			return out.toArray(new PcodeOp[0]);
			
		} else {
			System.out.println("Bad mode");
		}
		
		return null;
	}
}