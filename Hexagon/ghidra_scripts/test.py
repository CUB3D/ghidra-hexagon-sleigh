#@author CUB3D
#@category Qualcomm
#@runtime Jython

from ghidra.program.disassemble import Disassembler
from ghidra.app.util import PseudoDisassembler

for sel in currentSelection:
    for addr in sel:
        ins = getInstructionAt(addr)
        if ins is not None:
            ic = ins.instructionContext
            print(ic)
            print(ic.inputObjects)
            if ic is not None:
                pc = ic.processorContext
                print(pc)
                
                #print(pc.registers)

                hasext0 = pc.getRegister("hasext0")
                print(hasext0)
                hasext0 = pc.getValue(hasext0, False)
                print(hasext0)

                hasext0 = pc.getRegister("testctx")
                print(hasext0)
                hasext0 = pc.hasValue(hasext0)
                print(hasext0)

                dis = PseudoDisassembler(currentProgram)
                pi = dis.disassemble(addr)
                ic = pi.instructionContext
                print(ic.inputObjects)
                pc = ic.processorContext
                print(pc)

                hasext0 = pc.baseContextRegister
                print(hasext0)
                hasext0 = pc.hasValue(hasext0)
                print(hasext0)
                
                #print(pc.registers)


                
                #dis = Disassembler(currentProgram, None, None)
                #dis.disassemble(addr, None)
                #print(dis.disassemblerContext)
