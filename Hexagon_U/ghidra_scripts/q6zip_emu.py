# Decompress Q6ZIP compressed code sections
#@author CUB3D
#@category Qualcomm
#@runtime Jython

# A script for decompressing memory regions compressed with q6zip compression
# You might have to adjust out and input buffer addresses as well as sizes
# See: https://github.com/mzakocs/qualcomm_baseband_scripts/blob/main/dlpage_extractor_pixel_5.c
# See: https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/

from ghidra.pcode.memstate import MemoryFaultHandler
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

def write_memory(thread, offset, value):
    return thread.getState().setConcrete(toAddr(offset), value)

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
OUT_BUF = 0xD0000000
IN_BUF = 0xC5C70000
IN_BUF_END = 0xc6702e08
DECOMPRESS_FUNCTION = 0xc0bac220

# Pixel 5, March 2023
# this might actually be clade
#OUT_BUF = 0xD0000000
#IN_BUF = 0xCF600000
#IN_BUF_END = 0xCF70F3C9
#DECOMPRESS_FUNCTION = 0xc05eb420

# OnePlus 6, OnePlus6Oxygen_22.J.62_OTA_0620_all_2111252336_14afec75dd6fa
#OUT_BUF = 0xD0000000
#DECOMPRESS_FUNCTION = 0xd921b270
# NO INPUT BUFFER, not actually used

# OnePlus 7 Pro, GM1913_11.H.40_4400_202303231743
#OUT_BUF = 0xD0000000
#IN_BUF = 0xc8e30000
#IN_BUF_END = 0xc8e3f610
#DECOMPRESS_FUNCTION = 0xc0ce6980

END_OF_FUNCTION_MAGIC = 0xDEADBEEF

def main():
    global IN_BUF_END

    emu = PcodeEmulator(currentProgram.getLanguage())
    EmulatorUtilities.loadProgram(emu, currentProgram)

    out_size_addr = 0xF0000000
    STACK_START = 0xF8000000

    IN_BUF_END += (4 - (IN_BUF_END % 4)) # word align


    thread = emu.newThread()
    emu.addBreakpoint(toAddr(END_OF_FUNCTION_MAGIC), "1:1")
    init_emu(thread)

    dictionary = IN_BUF + 4
    index = dictionary + 0x5000
    out_buf_size = 0
    (number_of_blocks, ) = struct.unpack("<H", read_memory(thread, IN_BUF, 2))

    print("Decompressing", number_of_blocks, "blocks")
    current_block = 0
    while current_block < number_of_blocks:
        print(current_block, "/",number_of_blocks)
        block_ptr_addr = index + current_block * 4
        (block_ptr,) = struct.unpack("<I", read_memory(thread, block_ptr_addr, 4))

        block_size = IN_BUF_END - block_ptr
        if current_block + 1 < number_of_blocks:
            block_size_addr = index + (current_block + 1) * 4
            (tmp,) = struct.unpack("<I", read_memory(thread, block_size_addr, 4))
            block_size = tmp - block_ptr

        # Emulation state
        thread.overrideCounter(toAddr(DECOMPRESS_FUNCTION))
	    
        thread.overrideContextWithDefault()
        write_register(thread, "r0", OUT_BUF + out_buf_size)
        write_register(thread, "r1", out_size_addr)
        write_register(thread, "r2", block_ptr)
        write_register(thread, "r3", block_size)
        write_register(thread, "r4", dictionary)
        write_register(thread, "LR", END_OF_FUNCTION_MAGIC)
        write_register(thread, "SP", STACK_START)
        thread.reInitialize()

        write_memory(thread, out_size_addr, [0, 0, 0, 0])

        run_emu(emu, thread, fast=True)

        (out_size,) = struct.unpack("<I", read_memory(thread, out_size_addr, 4))

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
