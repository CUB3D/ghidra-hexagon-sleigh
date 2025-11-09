# A script for decompressing memory regions compressed with delta compression via dlpager
# You might have to adjust out and input buffer addresses
# See: https://github.com/mzakocs/qualcomm_baseband_scripts/blob/main/dlpage_extractor_pixel_5.c
# See: https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities
from ghidra.pcode.emulate import BreakCallBack
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

class UnimplNVCallback(BreakCallBack):
    def __init__(self):
        pass
    def pcodeCallback(self, _state):
        # print("_unimpl_nv()")
        return True

class DCacheZeroAddrCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        print("dcache_zero_addr()")
        return True


# Pixel 2, June 2020
OUT_BUF = 0xd11ca000
IN_BUF = 0xC6710000
DECOMPRESS_FUNCTION = 0xc0bac7bc

# Pixel 5, March 2023
# OUT_BUF = 0xD0379000
# IN_BUF = 0xCF710000
# DECOMPRESS_FUNCTION = 0xc05ebbd0


END_OF_FUNCTION_MAGIC = 0xDEADBEEF

def main():
    emuHelper = EmulatorHelper(currentProgram)
    emuHelper.registerCallOtherCallback("_unimpl_nv", UnimplNVCallback())
    emuHelper.registerCallOtherCallback("dcache_zero_addr", DCacheZeroAddrCallback())

    init_emu(emuHelper)

    index = IN_BUF + 4
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", emuHelper.readMemory(getAddress(IN_BUF), 2))

    current_block = 0
    while current_block < number_of_blocks:
        print(current_block, "/", number_of_blocks)
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_ptr_addr), 4))

        out_size = 0x1000

        emuHelper.writeRegister("r0", block_ptr)
        emuHelper.writeRegister("r1", OUT_BUF + out_buf_size)
        emuHelper.writeRegister("r2", out_size)
        emuHelper.writeRegister("LR", END_OF_FUNCTION_MAGIC)

        emuHelper.writeRegister(emuHelper.getPCRegister(), DECOMPRESS_FUNCTION)

        run_emu(emuHelper)

        current_block += 1
        out_buf_size += out_size

    decompressed_data = emuHelper.readMemory(getAddress(OUT_BUF), out_buf_size)
    setBytes(getAddress(OUT_BUF), decompressed_data)


    emuHelper.dispose()

def run_emu(emu, fast=True):
    while monitor.isCancelled() is False:

        # Are we done?
        executionAddress = emu.getExecutionAddress()
        if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
            return

        if not fast:
            # Dump current state
            print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))

            regs = ["r0", "r1", "r2", "r3", "r4"]
            for reg in regs:
                reg_value = emu.readRegister(reg)
                print("  {} = {:#018x}".format(reg, reg_value))

        if not fast:
            success = emu.step(monitor)
            if not success:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))
                return
        else:
            emu.run(monitor)
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
                return
            else:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))


main()
