#Decompress Delta/DLPager compressed data
#@author CUB3D
#@category Qualcomm
#@runtime Jython

# A script for decompressing memory regions compressed with delta compression via dlpager
# You might have to adjust out and input buffer addresses
# See: https://github.com/mzakocs/qualcomm_baseband_scripts/blob/main/dlpage_extractor_pixel_5.c
# See: https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/
# See: https://cub3d.pw/blog/01-qcom-delta/

from ghidra.pcode.emu import EmulatorUtilities
from ghidra.pcode.emu import PcodeEmulator
from ghidra.pcode.exec import InterruptPcodeExecutionException
from ghidra.pcode.exec import SuspendedPcodeExecutionException
from ghidra.program.model.lang import RegisterValue
from ghidra.util.task import CancelledListener
from java.lang import Throwable
from java.math import BigInteger
import struct

def write_register(thread, name, value):
    reg = currentProgram.getRegister(name)
    thread.getState().setRegisterValue(reg, RegisterValue(reg, BigInteger.valueOf(value)))

def read_memory(thread, offset, size):
    return thread.getState().inspectConcrete(toAddr(offset), size)

def init_emu(thread):
    """
    Zero out register state in emulator so you don't get uninit value errors
    :param thread:
    :return:
    """
    # Initialize state
    for reg in range(29):
        write_register(thread, "r"+str(reg), 0)
    for reg in range(4):
        write_register(thread, "p" + str(reg), 0)
    write_register(thread, "FP", 0)
    write_register(thread, "USR", 0)

# Pixel 2, June 2020
#OUT_BUF = 0xd11ca000
#IN_BUF = 0xC6710000
#DECOMPRESS_FUNCTION = 0xc0bac7bc

#Pixel 5, March 2023
OUT_BUF = 0xD0379000
IN_BUF = 0xCF710000
DECOMPRESS_FUNCTION = 0xc05ebbd0

# OnePlus 6, OnePlus6Oxygen_22.J.62_OTA_0620_all_2111252336_14afec75dd6fa
#OUT_BUF = 0xD05ed000
#IN_BUF = 0xc69ea000
#DECOMPRESS_FUNCTION = 0xd921ba30

# OnePlus 7 Pro, GM1913_11.H.40_4400_202303231743
#OUT_BUF = 0xD04F9000
#IN_BUF = 0xc8e30000
#DECOMPRESS_FUNCTION = 0xc0ce715c

END_OF_FUNCTION_MAGIC = 0xDEADBEEF
OUT_BLOCK_SIZE = 0x1000

def main():
    memory = currentProgram.getMemory()

    emu = PcodeEmulator(currentProgram.getLanguage())
    EmulatorUtilities.loadProgram(emu, currentProgram)

    thread = emu.newThread()
    emu.addBreakpoint(toAddr(END_OF_FUNCTION_MAGIC), "1:1")

    init_emu(thread)

    index = IN_BUF + 4
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", read_memory(thread, IN_BUF, 2))

    # Check we have an output region and its big enough
    out_block = memory.getBlock(toAddr(OUT_BUF))
    out_size_needed = number_of_blocks * OUT_BLOCK_SIZE

    if out_block is None:
        if out_size_needed > 0:
            print("OUT_BUF region missing, creating it")
            createMemoryBlock("DLPAGER_OUT", toAddr(OUT_BUF), [0]*out_size_needed, False)
    else:
        out_size_actual = out_block.getEnd().getOffset() - OUT_BUF + 1
        if out_size_actual < out_size_needed:
            print("OUT_BUF region at is too small, minimum size = 0x{:x} bytes".format(required_out_size))
            exit(0)

    # Decomp loop
    current_block = 0
    while current_block < number_of_blocks:
        print(current_block, "/", number_of_blocks)
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", read_memory(thread, block_ptr_addr, 4))
        print(hex(block_ptr))

        # block_ptr must be a valid ptr to mapped memory
        block = memory.getBlock(toAddr(block_ptr))
        if block is None:
            print("Invalid ptr in dlpager block table, check params. IN_BUF+4 should be a array of valid ptrs of length *(short*)(IN_BUF+0)")
            exit(0)

        out_size = OUT_BLOCK_SIZE

        write_register(thread, "r0", block_ptr)
        write_register(thread, "r1", OUT_BUF + out_buf_size)
        write_register(thread, "r2", out_size)
        write_register(thread, "LR", END_OF_FUNCTION_MAGIC)

        thread.overrideCounter(toAddr(DECOMPRESS_FUNCTION))
        thread.overrideContextWithDefault()
        thread.reInitialize()

        run_emu(emu, thread)

        current_block += 1
        out_buf_size += out_size

    decompressed_data = read_memory(thread, OUT_BUF, out_buf_size)
    setBytes(toAddr(OUT_BUF), decompressed_data)

def run_emu(emu, thread, fast=True):
    while monitor.isCancelled() is False:

        # Are we done?
        executionAddress = thread.getCounter()
        if executionAddress.getOffset() == END_OF_FUNCTION_MAGIC:
            return

        if not fast:
            # Dump current state
            print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))

            regs = ["r0", "r1", "r2", "r3", "r4"]
            for reg in regs:
                reg_value = thread.getState().inspectRegisterValue(
                    currentProgram.getRegister(reg)).getUnsignedValue()
                print("  {} = {:#018x}".format(reg, reg_value))

        if not fast:
            try:
                thread.stepInstruction()
            except InterruptPcodeExecutionException:
                thread.dropInstruction()
                if thread.getCounter().getOffset() == END_OF_FUNCTION_MAGIC:
                    return
                printerr("Emulation Error: 'Emulation interrupted at {}'".format(
                    thread.getCounter()))
                exit(0)
            except SuspendedPcodeExecutionException:
                thread.dropInstruction()
                return
            except Throwable as e:
                printerr("Emulation Error: '{}'".format(e))
                exit(0)
        else:
            try:
                thread.run()
            except InterruptPcodeExecutionException:
                thread.dropInstruction()
                if thread.getCounter().getOffset() == END_OF_FUNCTION_MAGIC:
                    return
                printerr("Emulation Error: 'Emulation interrupted at {}'".format(
                    thread.getCounter()))
                exit(0)
            except SuspendedPcodeExecutionException:
                thread.dropInstruction()
                return
            except Throwable as e:
                printerr("Emulation Error: '{}'".format(e))
                exit(0)


main()
