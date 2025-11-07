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

def getSymbolAddress(symbolName):
    symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName, None)
    if (symbol != None):
        return symbol.getAddress()
    else:
        raise("Failed to locate label: {}".format(symbolName))

class UnimplNVCallback(BreakCallBack):
    def __init__(self):
        pass
    def pcodeCallback(self, _state):
        print("_unimpl_nv()")
        return True

class DCacheZeroAddrCallback(BreakCallBack):
    def __init__(self):
        pass

    def pcodeCallback(self, _state):
        print("dcache_zero_addr()")
        return True


END_OF_FUNCTION_MAGIC = 0xDEADBEEF

def main():

    mainFunctionEntry = getSymbolAddress("delta_decompress")

    emuHelper = EmulatorHelper(currentProgram)
    emuHelper.registerCallOtherCallback("_unimpl_nv", UnimplNVCallback())
    emuHelper.registerCallOtherCallback("dcache_zero_addr", DCacheZeroAddrCallback())

    out_buf = 0xD0000000
    in_buf = 0xCF710000


    index = in_buf + 4
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", emuHelper.readMemory(getAddress(in_buf), 2))

    current_block = 0
    while current_block < number_of_blocks:
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_ptr_addr), 4))

        out_size = 0x1000

        emuHelper.writeRegister("r0", block_ptr)
        emuHelper.writeRegister("r1", out_buf + out_buf_size)
        emuHelper.writeRegister("r2", out_size)
        emuHelper.writeRegister("LR", END_OF_FUNCTION_MAGIC)

        # Set initial RIP
        mainFunctionEntryLong = int("0x{}".format(mainFunctionEntry), 16)
        emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)

        run_emu(emuHelper)

        current_block += 1
        out_buf_size += out_size

    decompressed_data = emuHelper.readMemory(getAddress(out_buf), out_buf_size)
    setBytes(getAddress(out_buf), decompressed_data)


    emuHelper.dispose()

def run_emu(emu):
    regs = ["r0", "r1", "r2", "r3", "r4"]

    while monitor.isCancelled() is False:

        # Are we done?
        executionAddress = emu.getExecutionAddress()
        if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
            print("Emulation complete.")
            return

        # Dump current state
        print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
        for reg in regs:
            reg_value = emu.readRegister(reg)
            print("  {} = {:#018x}".format(reg, reg_value))

        # Keep going
        success = emu.step(monitor)
        if not success:
            printerr("Emulation Error: '{}'".format(emu.getLastError()))
            return


main()
