#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Find and markup all QMI handler functions

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, VariableStorage
from ghidra.program.model.data import VoidDataType, PointerDataType, UnsignedIntegerDataType, CharDataType

memory = currentProgram.getMemory()

void_ptr = PointerDataType(VoidDataType.dataType)
char_ptr = PointerDataType(CharDataType.dataType)

dtm = currentProgram.getDataTypeManager()
parser = CParser(dtm)

qmi_typedef = parser.parse("""
typedef void (*qmi_function)(void*, void*, void*, void*);
""")

needle = "(qmi_svc_hdlr_ftype)"
strs = findStrings(None, len(needle), 1, True, False)

for s in strs:
    if needle != s.getString(memory)[:len(needle)]:
        continue
    addr = s.getAddress().getOffset()
    pattern = "\\x" + ("0"+hex(addr & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 8) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 16) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 24) & 0xFF)[2:-1])[-2:]
    matches = findBytes(currentProgram.getMinAddress(), pattern, 1, 4)
    
    if len(matches) != 1:
        print("Found wrong number of matches for", addr)
        continue
    
    name = s.getString(memory).replace(needle, "").strip()
    addr = matches[0]
    createLabel(addr, name+"_def", True)
    clearListing(addr, addr.add(0xc))
    createData(addr, char_ptr)
    createData(addr.add(4), qmi_typedef)
    createDWord(addr.add(8))
    
    addr = getInt(addr.add(4))
    func = createFunction(toAddr(addr), None)
    func.setName(name, SourceType.IMPORTED)
    func.replaceParameters(FunctionUpdateType.CUSTOM_STORAGE, False, SourceType.IMPORTED, [
        ParameterImpl("p0", void_ptr, VariableStorage.deserialize(currentProgram, "register:00000000:4"), currentProgram, SourceType.IMPORTED),
        ParameterImpl("cmd", void_ptr, VariableStorage.deserialize(currentProgram, "register:00000004:4"), currentProgram, SourceType.IMPORTED),
        ParameterImpl("p2", void_ptr, VariableStorage.deserialize(currentProgram, "register:00000008:4"), currentProgram, SourceType.IMPORTED),
        ParameterImpl("sdu", void_ptr, VariableStorage.deserialize(currentProgram, "register:0000000c:4"), currentProgram, SourceType.IMPORTED)
    ])