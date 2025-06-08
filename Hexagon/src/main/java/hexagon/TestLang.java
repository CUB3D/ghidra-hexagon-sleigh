package hexagon;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.processors.generic.MemoryBlockDefinition;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.ManualEntry;
import ghidra.util.task.TaskMonitor;

class TestLang implements Language {
	
	SleighLanguage l;
	
	public TestLang(SleighLanguage l) {
		this.l = l;
	}

	@Override
	public LanguageID getLanguageID() {
		return l.getLanguageID();
	}

	@Override
	public LanguageDescription getLanguageDescription() {
		// TODO Auto-generated method stub
		return l.getLanguageDescription();
	}

	@Override
	public ParallelInstructionLanguageHelper getParallelInstructionHelper() {
		// TODO Auto-generated method stub
		return l.getParallelInstructionHelper();
	}

	@Override
	public Processor getProcessor() {
		// TODO Auto-generated method stub
		return l.getProcessor();
	}

	@Override
	public int getVersion() {
		// TODO Auto-generated method stub
		return l.getVersion();
	}

	@Override
	public int getMinorVersion() {
		// TODO Auto-generated method stub
		return l.getMinorVersion();
	}

	@Override
	public AddressFactory getAddressFactory() {
		// TODO Auto-generated method stub
		return l.getAddressFactory();
	}

	@Override
	public AddressSpace getDefaultSpace() {
		// TODO Auto-generated method stub
		return l.getDefaultSpace();
	}

	@Override
	public AddressSpace getDefaultDataSpace() {
		// TODO Auto-generated method stub
		return l.getDefaultDataSpace();
	}

	@Override
	public boolean isBigEndian() {
		// TODO Auto-generated method stub
		return l.isBigEndian();
	}

	@Override
	public int getInstructionAlignment() {
		// TODO Auto-generated method stub
		return l.getInstructionAlignment();
	}

	@Override
	public boolean supportsPcode() {
		// TODO Auto-generated method stub
		return l.supportsPcode();
	}

	@Override
	public boolean isVolatile(Address addr) {
		// TODO Auto-generated method stub
		return l.isVolatile(addr);
	}

	@Override
	public InstructionPrototype parse(MemBuffer buf, ProcessorContext context, boolean inDelaySlot)
			throws InsufficientBytesException, UnknownInstructionException {
		System.out.println("PARSE: " + buf.getAddress());
		// TODO Auto-generated method stub
		return l.parse(buf, context, inDelaySlot);
	}

	@Override
	public int getNumberOfUserDefinedOpNames() {
		// TODO Auto-generated method stub
		return l.getNumberOfUserDefinedOpNames();
	}

	@Override
	public String getUserDefinedOpName(int index) {
		// TODO Auto-generated method stub
		return l.getUserDefinedOpName(index);
	}

	@Override
	public Register[] getRegisters(Address address) {
		// TODO Auto-generated method stub
		return l.getRegisters(address);
	}

	@Override
	public Register getRegister(AddressSpace addrspc, long offset, int size) {
		// TODO Auto-generated method stub
		return l.getRegister(addrspc, offset, size);
	}

	@Override
	public List<Register> getRegisters() {
		// TODO Auto-generated method stub
		return l.getRegisters();
	}

	@Override
	public List<String> getRegisterNames() {
		// TODO Auto-generated method stub
		return l.getRegisterNames();
	}

	@Override
	public Register getRegister(String name) {
		// TODO Auto-generated method stub
		return l.getRegister(name);
	}

	@Override
	public Register getRegister(Address addr, int size) {
		// TODO Auto-generated method stub
		return l.getRegister(addr, size);
	}

	@Override
	public Register getProgramCounter() {
		// TODO Auto-generated method stub
		return l.getProgramCounter();
	}

	@Override
	public Register getContextBaseRegister() {
		// TODO Auto-generated method stub
		return l.getContextBaseRegister();
	}

	@Override
	public List<Register> getContextRegisters() {
		// TODO Auto-generated method stub
		return l.getContextRegisters();
	}

	@Override
	public MemoryBlockDefinition[] getDefaultMemoryBlocks() {
		// TODO Auto-generated method stub
		return l.getDefaultMemoryBlocks();
	}

	@Override
	public List<AddressLabelInfo> getDefaultSymbols() {
		// TODO Auto-generated method stub
		return l.getDefaultSymbols();
	}

	@Override
	public String getSegmentedSpace() {
		// TODO Auto-generated method stub
		return l.getSegmentedSpace();
	}

	@Override
	public AddressSetView getVolatileAddresses() {
		// TODO Auto-generated method stub
		return l.getVolatileAddresses();
	}

	@Override
	public void applyContextSettings(DefaultProgramContext ctx) {
		// TODO Auto-generated method stub
		l.applyContextSettings(ctx);
	}

	@Override
	public void reloadLanguage(TaskMonitor taskMonitor) throws IOException {
		// TODO Auto-generated method stub
		l.reloadLanguage(taskMonitor);
		
	}

	@Override
	public List<CompilerSpecDescription> getCompatibleCompilerSpecDescriptions() {
		// TODO Auto-generated method stub
		return l.getCompatibleCompilerSpecDescriptions();
	}

	@Override
	public CompilerSpec getCompilerSpecByID(CompilerSpecID compilerSpecID) throws CompilerSpecNotFoundException {
		// TODO Auto-generated method stub
		return l.getCompilerSpecByID(compilerSpecID);
	}

	@Override
	public CompilerSpec getDefaultCompilerSpec() {
		// TODO Auto-generated method stub
		return l.getDefaultCompilerSpec();
	}

	@Override
	public boolean hasProperty(String key) {
		// TODO Auto-generated method stub
		return l.hasProperty(key);
	}

	@Override
	public int getPropertyAsInt(String key, int defaultInt) {
		// TODO Auto-generated method stub
		return l.getPropertyAsInt(key, defaultInt);
	}

	@Override
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean) {
		// TODO Auto-generated method stub
		return l.getPropertyAsBoolean(key, defaultBoolean);
	}

	@Override
	public String getProperty(String key, String defaultString) {
		// TODO Auto-generated method stub
		return l.getProperty(key, defaultString);
	}

	@Override
	public String getProperty(String key) {
		// TODO Auto-generated method stub
		return l.getProperty(key);
	}

	@Override
	public Set<String> getPropertyKeys() {
		// TODO Auto-generated method stub
		return l.getPropertyKeys();
	}

	@Override
	public boolean hasManual() {
		// TODO Auto-generated method stub
		return l.hasManual();
	}

	@Override
	public ManualEntry getManualEntry(String instructionMnemonic) {
		// TODO Auto-generated method stub
		return l.getManualEntry(instructionMnemonic);
	}

	@Override
	public Set<String> getManualInstructionMnemonicKeys() {
		// TODO Auto-generated method stub
		return l.getManualInstructionMnemonicKeys();
	}

	@Override
	public Exception getManualException() {
		// TODO Auto-generated method stub
		return l.getManualException();
	}

	@Override
	public List<Register> getSortedVectorRegisters() {
		// TODO Auto-generated method stub
		return l.getSortedVectorRegisters();
	}

	@Override
	public AddressSetView getRegisterAddresses() {
		// TODO Auto-generated method stub
		return l.getRegisterAddresses();
	}
	
}	
