#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Find and markup all QuRT task structs

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, VariableStorage
from ghidra.program.model.data import VoidDataType, PointerDataType, UnsignedIntegerDataType, CharDataType

memory = currentProgram.getMemory()

dtm = currentProgram.getDataTypeManager()
parser = CParser(dtm)

# V1 = Samsung S5
# V2 = Pixel 2/2xl/5
VERSION=2

if VERSION == 1:
	qurt_task = parser.parse("""
		typedef void (*qurt_task_func)();
		
		struct qurt_task {
			char* name;
			int unk1;
			qurt_task_func func;
			int unk3;
			int unk5;
			int unk6;
			void* unk10;
		};
	""")
	ENTRY_OFFSET = 2*4
	CLEAR_SIZE = 7*4
elif VERSION == 2:
	qurt_task = parser.parse("""
		typedef void (*qurt_task_func)();
		
		struct qurt_task {
			char* name;
			int unk1;
			int unk2;
			qurt_task_func func;
			int unk3;
			char* unk4;
			int unk5;
			int unk6;
			int unk7;
			char* unk8;
			void* unk9;
			void* unk10;
		};
	""")
	ENTRY_OFFSET = 3*4
	CLEAR_SIZE = 11*4
else:
	print("Unknown version")
	exit(0)



needle = b"a2_log\0"
strs = findBytes(currentProgram.getMinAddress(), needle)
if strs is None:
	print("Failed to find tasks")
	exit(0)

print(strs)
addr = strs.getOffset()
pattern = "\\x" + ("0"+hex(addr & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 8) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 16) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 24) & 0xFF)[2:-1])[-2:]
matches = findBytes(currentProgram.getMinAddress(), pattern, 2, 4)
first_struct = None
for m in matches:
	after_m = toAddr(getLong(m.add(4)) & 0xFFFFFFFF)
	if getMemoryBlock(after_m) is not None:
		print("not non", m)
		first_struct = m

if first_struct is None:
	print("Failed to find first task struct")
	exit(0)
	
task = first_struct.add(-8)
safe_limit = 0
while True:
	name_p = toAddr(getLong(task) & 0xFFFFFFFF)
	task_p = toAddr(getLong(task.add(4)) & 0xFFFFFFFF)
	if name_p.getOffset() == 0 or task_p.getOffset() == 0:
		break
	
	clearListing(name_p, name_p.add(1))
	try:
		name = createAsciiString(name_p).getValue()
	except:
		name = "unknown"
	print("Marking task: ", name, "@", name_p, task_p)
	try:
		clearListing(task_p, task_p.add(CLEAR_SIZE))
		createData(task_p, qurt_task)
	except:
		pass
		
	entry_p = toAddr(getLong(task_p.add(ENTRY_OFFSET)) & 0xFFFFFFFF)
	try:
		createFunction(entry_p, "task_" + name + "_entry")
	except:
		pass
	try:
		disassemble(entry_p)
	except:
		pass
		
	task = task.add(8)
	safe_limit += 1
	if safe_limit > 500:
		break
	
