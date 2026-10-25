#Emulate Hexagon code
#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Emulating QDSP6 functions

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

class HaltMemoryFaultHandler(MemoryFaultHandler):
    def uninitializedRead(self, a, s, b, bo):
        print("Uninit read(", a, s, ")")
        exit()

    def unknownAddress(self, a, w):
        print("Unk addr")
        exit()

END_OF_FUNCTION_MAGIC = 0xDEADBEEF
START_ADDR = 0xc05eb400
END_ADDR = 0xc05eb414

def main():
    emu = PcodeEmulator(currentProgram.getLanguage())
    EmulatorUtilities.loadProgram(emu, currentProgram)

    STACK_START = 0xF8000000

    thread = emu.newThread()
    emu.addBreakpoint(toAddr(END_OF_FUNCTION_MAGIC), "1:1")
    init_emu(thread)

    # Emulation state
    thread.overrideCounter(toAddr(START_ADDR))
    write_register(thread, "LR", END_OF_FUNCTION_MAGIC)
    write_register(thread, "SP", STACK_START)
    thread.overrideContextWithDefault()
    thread.reInitialize()

    run_emu(emu, thread, fast=False)

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
