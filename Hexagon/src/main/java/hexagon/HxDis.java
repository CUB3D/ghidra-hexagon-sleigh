package hexagon;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompileCallback;
import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.PcodeEmitPacked;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.ParserContext;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProcessorContextView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PatchEncoder;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.ProgramContextImpl;
import ghidra.util.ManualEntry;
import ghidra.util.task.TaskMonitor;

public class HxDis extends Disassembler {
	
	public HxDis(Program program, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		super(program, isMarkBadDisassemblyOptionEnabled(program),
			isMarkUnimplementedPcodeOptionEnabled(program), isRestrictToExecuteMemory(program),
			monitor, listener);
		System.out.println("ctor1");

	}

	public HxDis(Language language, AddressFactory addrFactory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		super(new TestLang((SleighLanguage) language), addrFactory, monitor, listener);
		System.out.println("ctor2");
	}
	
	public HxDis(Program program, Language language, AddressFactory addrFactory,
			boolean markBadInstructions, boolean markUnimplementedPcode,
			boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {

		super(program, markBadInstructions, markUnimplementedPcode, restrictToExecuteMemory, monitor, listener);
		System.out.println("ctor3");
	}
	
	public HxDis(Program program, boolean markBadInstructions,
			boolean markUnimplementedPcode, boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		this(program, new TestLang((SleighLanguage) program.getLanguage()), program.getAddressFactory(), markBadInstructions,
			markUnimplementedPcode, restrictToExecuteMemory, monitor, listener);
		System.out.println("ctor4");
	}
	
	@Override
	protected InstructionPrototype parseInstructionPrototype(MemBuffer instrMemBuffer, InstructionBlock block)
			throws InsufficientBytesException, UnknownInstructionException {
		System.out.println("Test: " + block.getStartAddress());
		// TODO Auto-generated method stub
		return new TestIP((SleighInstructionPrototype)super.parseInstructionPrototype(instrMemBuffer, block));
	}

	
	class TestIP implements InstructionPrototype {
		
		private SleighInstructionPrototype p;
		
		public TestIP(SleighInstructionPrototype p) {
			this.p = p;
		}

		@Override
		public ParserContext getParserContext(MemBuffer buf, ProcessorContextView processorContext)
				throws MemoryAccessException {
			// TODO Auto-generated method stub
			return p.getParserContext(buf, processorContext);
		}

		@Override
		public ParserContext getPseudoParserContext(Address addr, MemBuffer buffer,
				ProcessorContextView processorContext) throws InsufficientBytesException, UnknownInstructionException,
				UnknownContextException, MemoryAccessException {
			// TODO Auto-generated method stub
			return p.getPseudoParserContext(addr, buffer, processorContext);
		}

		@Override
		public boolean hasDelaySlots() {
			return p.hasDelaySlots();
		}

		@Override
		public boolean hasCrossBuildDependency() {
			return p.hasCrossBuildDependency();
		}

		@Override
		public String getMnemonic(ghidra.program.model.lang.InstructionContext context) {
			return p.getMnemonic(context);
		}

		@Override
		public int getLength() {
			return p.getLength();
		}

		@Override
		public Mask getInstructionMask() {
			return p.getInstructionMask();
		}

		@Override
		public Mask getOperandValueMask(int operandIndex) {
			return p.getOperandValueMask(operandIndex);
		}

		@Override
		public FlowType getFlowType(ghidra.program.model.lang.InstructionContext context) {
			return p.getFlowType(context);
		}

		@Override
		public int getDelaySlotDepth(ghidra.program.model.lang.InstructionContext context) {
			return p.getDelaySlotDepth(context);
		}

		@Override
		public int getDelaySlotByteCount() {
			return p.getDelaySlotByteCount();
		}

		@Override
		public boolean isInDelaySlot() {
			return p.isInDelaySlot();
		}

		@Override
		public int getNumOperands() {
			return p.getNumOperands();
		}

		@Override
		public int getOpType(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getOpType(opIndex, context);
		}

		@Override
		public Address getFallThrough(ghidra.program.model.lang.InstructionContext context) {
			return p.getFallThrough(context);
		}

		@Override
		public int getFallThroughOffset(ghidra.program.model.lang.InstructionContext context) {
			return p.getFallThroughOffset(context);
		}

		@Override
		public Address[] getFlows(ghidra.program.model.lang.InstructionContext context) {
			return p.getFlows(context);
		}

		@Override
		public String getSeparator(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getSeparator(opIndex, context);
		}

		@Override
		public ArrayList<Object> getOpRepresentationList(int opIndex,
				ghidra.program.model.lang.InstructionContext context) {
			return p.getOpRepresentationList(opIndex, context);
		}

		@Override
		public Address getAddress(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getAddress(opIndex, context);
		}

		@Override
		public Scalar getScalar(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getScalar(opIndex, context);
		}

		@Override
		public Register getRegister(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getRegister(opIndex, context);
		}

		@Override
		public Object[] getOpObjects(int opIndex, ghidra.program.model.lang.InstructionContext context) {
			return p.getOpObjects(opIndex, context);
		}

		@Override
		public RefType getOperandRefType(int opIndex, ghidra.program.model.lang.InstructionContext context,
				PcodeOverride override) {
			return p.getOperandRefType(opIndex, context, override);
		}

		@Override
		public boolean hasDelimeter(int opIndex) {
			return p.hasDelimeter(opIndex);
		}

		@Override
		public Object[] getInputObjects(ghidra.program.model.lang.InstructionContext context) {
			return p.getInputObjects(context);
		}

		@Override
		public Object[] getResultObjects(ghidra.program.model.lang.InstructionContext context) {
			return p.getResultObjects(context);
		}

		@Override
		public PcodeOp[] getPcode(ghidra.program.model.lang.InstructionContext context, PcodeOverride override) {
			System.out.println("Getpcode2: ");
			
			Varnode x0 = convertRegisterToVarnode(getLanguage().getRegister("X0"));
			PcodeOp[] ops = new PcodeOp[] {
					new PcodeOp(context.getAddress(), 0, PcodeOp.COPY, new Varnode[] { x0}, x0),
			};
			return ops;

			// TODO Auto-generated method stub
//			return p.getPcode(context, override);
		}

		@Override
		public void getPcodePacked(PatchEncoder encoder, ghidra.program.model.lang.InstructionContext context,
				PcodeOverride override) throws IOException {
			
			System.out.println("Getpcodepack: ");

			try {
				
				PcodeOp[] ops = getPcode(context, 0);
				
			DecompileCallback.encodeInstruction(encoder, context.getAddress(), ops, p.getLength(), 0, this.p.getLanguage().getAddressFactory());
			} catch (Exception e) {
				e.printStackTrace();
			}
			return;

		}
		
		private Varnode convertRegisterToVarnode(Register reg) {
			Varnode vn = new Varnode(reg.getAddress(), reg.getBitLength() / 8);
			return vn;
		}

		@Override
		public PcodeOp[] getPcode(ghidra.program.model.lang.InstructionContext context, int opIndex) {
			System.out.println("Getpcode: ");
			
//			return new PcodeOp[] {
//					new PcodeOp(context.getAddress(), 0, PcodeOp.RETURN),
//			};
			
			Varnode x0 = convertRegisterToVarnode(getLanguage().getRegister("X0"));
			PcodeOp[] ops = new PcodeOp[] {
					new PcodeOp(context.getAddress(), 0, PcodeOp.COPY, new Varnode[] { x0}, x0),
			};
			return ops;
			
			// TODO Auto-generated method stub
//			return p.getPcode(context, opIndex);
		}

		@Override
		public Language getLanguage() {
			return p.getLanguage();
		}
		
	}
	
	
}
