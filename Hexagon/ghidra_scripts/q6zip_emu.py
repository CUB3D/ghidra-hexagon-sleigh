# A script for decompressing memory regions compressed with q6zip compression
# You might have to adjust out and input buffer addresses as well as sizes
# See: https://github.com/mzakocs/qualcomm_baseband_scripts/blob/main/dlpage_extractor_pixel_5.c
# See: https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/

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

class HaltMemoryFaultHandler(MemoryFaultHandler):
    def uninitializedRead(self, a, s, b, bo):
        print("Uninit read(", a, s, ")")
        # exit()

    def unknownAddress(self, a, w):
        print("Unk addr")
        exit()


# Pixel 2, June 2020
OUT_BUF = 0xD0000000
IN_BUF = 0xC5C70000
IN_BUF_END = 0xc6702e08
DECOMPRESS_FUNCTION = 0xc0bac220

# Pixel 5, March 2023
# this might actually be clade
# OUT_BUF = 0xD0000000
# IN_BUF = 0xCF600000
# IN_BUF_END = 0xCF70F3C9
# DECOMPRESS_FUNCTION = 0xc05eb420

END_OF_FUNCTION_MAGIC = 0xDEADBEEF

def main():
    global IN_BUF_END

    emuHelper = EmulatorHelper(currentProgram)
    emuHelper.registerCallOtherCallback("dcache_zero_addr", DCacheZeroAddrCallback())
    emuHelper.registerCallOtherCallback("l2fetch", L2FetchCallback())
    emuHelper.registerCallOtherCallback("dcache_fetch", DCacheFetchCallback())
    emuHelper.registerCallOtherCallback("isync", IsyncCallback())
    emuHelper.setMemoryFaultHandler(HaltMemoryFaultHandler())

    out_size_addr = 0xF0000000
    STACK_START = 0xF8000000

    IN_BUF_END += (4 - (IN_BUF_END % 4)) # word align


    dictionary = IN_BUF + 4
    index = dictionary + 0x5000
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", emuHelper.readMemory(getAddress(IN_BUF), 2))

    print("Decompressing", number_of_blocks, "blocks")
    current_block = 0
    while current_block < number_of_blocks:
        print(current_block, "/",number_of_blocks)
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_ptr_addr), 4))

        block_size = IN_BUF_END - block_ptr
        if current_block + 1 < number_of_blocks:
            block_size_addr = index + (current_block + 1) * 4
            (tmp,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_size_addr), 4))
            block_size = tmp - block_ptr

        init_emu(emuHelper)

        # Emulation state

        emuHelper.writeMemory(getAddress(out_size_addr), [0, 0, 0, 0])

        emuHelper.writeRegister("r0", OUT_BUF + out_buf_size)
        emuHelper.writeRegister("r1", out_size_addr)
        emuHelper.writeRegister("r2", block_ptr)
        emuHelper.writeRegister("r3", block_size)
        emuHelper.writeRegister("r4", dictionary)
        emuHelper.writeRegister("LR", END_OF_FUNCTION_MAGIC)
        emuHelper.writeRegister("SP", STACK_START)

        emuHelper.writeRegister(emuHelper.getPCRegister(), DECOMPRESS_FUNCTION)

        run_emu(emuHelper, fast=True)

        (out_size,) = struct.unpack("<I", emuHelper.readMemory(getAddress(out_size_addr), 4))

        current_block += 1
        out_buf_size += out_size


    decompressed_data = emuHelper.readMemory(getAddress(OUT_BUF), out_buf_size)
    setBytes(getAddress(OUT_BUF), decompressed_data)


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
        else:
            try:
                emu.run(monitor)
            except:
                pass
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
                return
            else:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))




main()
