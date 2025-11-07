# A script for decompressing memory regions compressed with q6zip compression
# You might have to adjust out and input buffer addresses as well as sizes
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
        #print("_unimpl_nv()")
        return True

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


END_OF_FUNCTION_MAGIC = 0xDEADBEEF

def main():

    mainFunctionEntry = getSymbolAddress("q6zip_decompress")
    mainFunctionEntryLong = int("0x{}".format(mainFunctionEntry), 16)

    emuHelper = EmulatorHelper(currentProgram)
    emuHelper.registerCallOtherCallback("_unimpl_nv", UnimplNVCallback())
    emuHelper.registerCallOtherCallback("dcache_zero_addr", DCacheZeroAddrCallback())
    emuHelper.registerCallOtherCallback("l2fetch", L2FetchCallback())
    emuHelper.registerCallOtherCallback("dcache_fetch", DCacheFetchCallback())

    out_buf = 0xD0000000
    in_buf = 0xCF600000
    in_buf_end = 0xCF70F3C9
    out_size_addr = 0xF0000000

    in_buf_end += (4 - (in_buf_end % 4)) # word align


    dictionary = in_buf + 4
    index = dictionary + 0x5000
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", emuHelper.readMemory(getAddress(in_buf), 2))

    print("Decompressing", number_of_blocks, "blocks")
    current_block = 0
    while current_block < number_of_blocks:
        print(current_block, "/",number_of_blocks)
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_ptr_addr), 4))

        block_size = in_buf_end - block_ptr
        if current_block + 1 < number_of_blocks:
            block_size_addr = index + (current_block + 1) * 4
            (tmp,) = struct.unpack("<I", emuHelper.readMemory(getAddress(block_size_addr), 4))
            block_size = tmp - block_ptr

        emuHelper.writeRegister("r0", out_buf + out_buf_size)
        emuHelper.writeRegister("r1", out_size_addr)
        emuHelper.writeRegister("r2", block_ptr)
        emuHelper.writeRegister("r3", block_size)
        emuHelper.writeRegister("r4", dictionary)
        emuHelper.writeRegister("LR", END_OF_FUNCTION_MAGIC)

        # Set initial RIP
        emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)

        run_emu(emuHelper, fast=False)

        (out_size,) = struct.unpack("<I", emuHelper.readMemory(getAddress(out_size_addr), 4))

        current_block += 1
        out_buf_size += out_size

        if current_block > 1:
            break


    decompressed_data = emuHelper.readMemory(getAddress(out_buf), out_buf_size)
    print(decompressed_data)
    print(list(filter(lambda x: x != 0, decompressed_data)))
    setBytes(getAddress(out_buf), decompressed_data)


    emuHelper.dispose()

def run_emu(emu, fast=True):
    while monitor.isCancelled() is False:

        if not fast:
            # Are we done?
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
                return

            # Dump current state
            print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
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
            emu.run(monitor)
            executionAddress = emu.getExecutionAddress()
            if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
                return
            else:
                printerr("Emulation Error: '{}'".format(emu.getLastError()))




main()
