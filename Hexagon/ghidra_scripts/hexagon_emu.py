#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Emulating QDSP6 functions

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.pcode.emulate import BreakCallBack
from ghidra.pcode.memstate import MemoryFaultHandler
import struct

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def init_emu(emuHelper):
    """
    Zero out register state in emulator so you don't get uninit value errors
    :param emuHelper:
    :return:
    """
    # Initialize state
    for reg in range(29):
        emuHelper.writeRegister("r"+str(reg), 0)
    for reg in range(4):
        emuHelper.writeRegister("p" + str(reg), 0)
    emuHelper.writeRegister("FP", 0)
    emuHelper.writeRegister("USR", 0)

class DCacheZeroAddrCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        #print("dcache_zero_addr()")
        return True

class L2FetchCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        #print("l2fetch()")
        return True


class DCacheFetchCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        #print("dcache_fetch()")
        return True

class IsyncCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        return True
        
class CswiCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        return True

class CiadCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        return True

class MemwPhysCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        return True

class HaltMemoryFaultHandler(MemoryFaultHandler):
    def uninitializedRead(self, a, s, b, bo):
        print("Uninit read(", a, s, ")")
        # exit()

    def unknownAddress(self, a, w):
        print("Unk addr")
        exit()

END_OF_FUNCTION_MAGIC = 0xDEADBEEF
START_ADDR = 0xc00cc2e0
END_ADDR = 0xc00d42a8

def main():
    emuHelper = EmulatorHelper(currentProgram)
    emuHelper.registerCallOtherCallback("dcache_zero_addr", DCacheZeroAddrCallback())
    emuHelper.registerCallOtherCallback("l2fetch", L2FetchCallback())
    emuHelper.registerCallOtherCallback("dcache_fetch", DCacheFetchCallback())
    emuHelper.registerCallOtherCallback("isync", IsyncCallback())
    emuHelper.registerCallOtherCallback("cswi", CswiCallback())
    emuHelper.registerCallOtherCallback("ciad", CiadCallback())
    emuHelper.registerCallOtherCallback("memw_phys", MemwPhysCallback())
    emuHelper.setMemoryFaultHandler(HaltMemoryFaultHandler())

    STACK_START = 0xF8000000

    
    init_emu(emuHelper)

    # Emulation state
    emuHelper.writeRegister(emuHelper.getPCRegister(), START_ADDR)
    emuHelper.writeRegister("LR", END_OF_FUNCTION_MAGIC)
    emuHelper.writeRegister("SP", STACK_START)

    run_emu(emuHelper, fast=False)
    
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0xc00d4334), 4))[0]))
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0xc00d4328), 4))[0]))
    
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0x045D0000), 4))[0]))
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0x045D0000+0x10), 4))[0]))
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0x045D0000+0x14), 4))[0]))
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0x045D0000+0x18), 4))[0]))
    print(hex(struct.unpack("<I", emuHelper.readMemory(toAddr(0x045D0000+0x1c), 4))[0]))
    
    emuHelper.dispose()

def run_emu(emu, fast=True):
    while monitor.isCancelled() is False:

        if not fast:
            # Are we done?
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
                return

            # Dump current state
            inst = getInstructionAt(executionAddress)
            print("Address: 0x{} ({})".format(executionAddress, inst))
            # If the instruction isn't disassembled in ghidra then it might have unresolved dotnew
            if "None" == str(inst):
                exit()
            for reg in ["r0", "r1", "r2", "r3", "r4", "r5"]:
                reg_value = emu.readRegister(reg)
                print("  {} = {:#018x}".format(reg, reg_value))

        # Keep going
        if not fast:
            success = emu.step(monitor)
            if not success:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))
                return
            if emu.getExecutionAddress().getOffset() == END_ADDR:
                return
        else:
            try:
                emu.run(monitor)
            except:
                pass
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC or executionAddress.getOffset() == END_ADDR:
                return
            else:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))
                return




main()
