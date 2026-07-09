# Annotate Qualcomm classes by RTTI
#@author CUB3D
#@category Qualcomm
#@runtime Jython

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, VariableStorage
from ghidra.program.model.data import VoidDataType, PointerDataType, UnsignedIntegerDataType, CharDataType

void_ptr = PointerDataType(VoidDataType.dataType)

memory = currentProgram.getMemory()

dtm = currentProgram.getDataTypeManager()
parser = CParser(dtm)

cxx_type_info_root = parser.parse("""
struct cxx_type_info_root {
    void* vtable;
    char* name;
};
""")

cxx_type_info = parser.parse("""
struct cxx_type_info {
    void* vtable;
    char* name;
    cxx_type_info_root* next_typeinfo;
};
""")

cxx_type_info_vtbl_ref_short = parser.parse("""
struct cxx_type_info_vtbl_ref_short {
    void* vtable;
    char* name;
    void* vtable2;
};
""")

cxx_type_info_vtbl_ref_long = parser.parse("""
struct cxx_type_info_vtbl_ref_long {
    void* vtable;
    char* name;
    void* vtable2;
    char* name2;
    void* vtable3;
};
""")

transaction = dtm.startTransaction("Adding RTTI structs")
dtm.addDataType(cxx_type_info_root, None)
dtm.addDataType(cxx_type_info, None)
dtm.addDataType(cxx_type_info_vtbl_ref_short, None)
dtm.addDataType(cxx_type_info_vtbl_ref_long, None)
dtm.endTransaction(transaction, True)

def find_str(needle):
	strs = findBytes(currentProgram.getMinAddress(), needle)
	if strs is None:
		print("Failed to find str")
		exit(0)
	
	addr = strs.getOffset()
	return addr

def find_num_single(addr):
	pattern = "\\x" + ("0"+hex(addr & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 8) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 16) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 24) & 0xFF)[2:-1])[-2:]
	matches = findBytes(currentProgram.getMinAddress(), pattern)
	return matches.getOffset()
	
def find_num(addr):
	pattern = "\\x" + ("0"+hex(addr & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 8) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 16) & 0xFF)[2:-1])[-2:] + "\\x" + ("0"+hex((addr >> 24) & 0xFF)[2:-1])[-2:]
	matches = findBytes(currentProgram.getMinAddress(), pattern, 0, 4)
	
	r = []
	for s in matches:
		r += [s.getOffset()]
	return r

def mark_vtable(x, name):
	print "VT @ ", x 
	try:
		createData(x.add(-4), void_ptr) # always 0
	except:
		pass
	try:
		createData(x, void_ptr)
	except:
		pass
	try:
		createData(x.add(4), void_ptr)
	except:
		pass
	createLabel(x, name + "_typeinfo", True)
	createLabel(x.add(4), name + "_vtable", True)
	i = 4
	while True:
		ptr = getLong(x.add(i)) & 0xFFFFFFFF
		if ptr == 0:
			break
		if not toAddr(ptr).isLoadedMemoryAddress():
			break
		try:
			clearListing(x.add(i), x.add(i).add(4))
			createData(x.add(i), void_ptr)
		except:
			break
		#try:
		createFunction(toAddr(ptr), None)
		#except:
		#	pass
		i += 4
	

def mark_typeinfo(x, name, indent=1):
	# This is the vtable
	if getLong(x.add(-4)) & 0xFFFFFFFF == 0:
		mark_vtable(x, name)
		return
	# Some things sneak past that
	if getLong(x.add(-4)) & 0xFFFFFFFF < 0x01000000:
		return
	#print(x)
	typeinfo_base = x.add(-8)
	
	str_addr = toAddr(getLong(typeinfo_base.add(4)) & 0xFFFFFFFF)
	#print("S", str_addr)
	try:
		name = createAsciiString(str_addr).getValue()
		if len(name) == 0:
			return # pointer to random data
		createLabel(typeinfo_base, name, True)
	except:
		name = getDataAt(str_addr)
		if name is None:
			print("BAD NAME @", str_addr)
			return
		name = name.getValue()
		#print(name)
		#print(type(name))
		
		if ("unicode" not in str(type(name))) or len(name) == 0:
			return # pointer to random data
		try:
			createLabel(typeinfo_base, name, True)
		except:
			return # name isn't a string?
	
	print("- " * indent, x, "=", name)
	
	clearListing(typeinfo_base, typeinfo_base.add(0xc))
	createData(typeinfo_base, cxx_type_info)
	
	for y in find_num(typeinfo_base.getOffset()):
		mark_typeinfo(toAddr(y), name, indent + 1)
		
		
	vtbl_addr = toAddr(getLong(typeinfo_base) & 0xFFFFFFFF)

	for x in find_num(vtbl_addr.getOffset()):
		mark_typeinfo_vtbl_ref(toAddr(x), name)

def mark_typeinfo_vtbl_ref(x, name):
	
	if getLong(x.add(-4)) & 0xFFFFFFFF == 0:
		mark_vtable(x, name)
		return # vtable
	
	print "VTR @", x
	
	v1 = getLong(x) & 0xFFFFFFFF
	v2 = getLong(x.add(4)) & 0xFFFFFFFF
	v3 = getLong(x.add(8)) & 0xFFFFFFFF
	v4 = getLong(x.add(12)) & 0xFFFFFFFF
	v5 = getLong(x.add(16)) & 0xFFFFFFFF 
	
	str_addr = toAddr(getLong(x.add(4)) & 0xFFFFFFFF)
	try:
		name = createAsciiString(str_addr).getValue()
		if len(name) == 0:
			return # pointer to random data
		createLabel(x, name, True)
	except:
		name = getDataAt(str_addr)
		if name is None:
			return
		name = name.getValue()
		if ("unicode" not in str(type(name))) or len(name) == 0:
			return # pointer to random data
		try:
			createLabel(x, name, True)
		except:
			return # name isn't a string?
	
	if (v5 == 0) or (v4 == 0) or toAddr(v5).isNonLoadedMemoryAddress() or toAddr(v4).isNonLoadedMemoryAddress():
		 kind = cxx_type_info_vtbl_ref_short
		 clearListing(x, x.add(4*3))
	else:
		kind = cxx_type_info_vtbl_ref_long
		clearListing(x, x.add(4*5))
	
	try:
		createData(x, kind)
	except:
		pass
		
	for x in find_num(x.getOffset()):
		mark_typeinfo_vtbl_ref(toAddr(x), name)

def mark_typeinfo_root(name):
	name_str = str(name[:-1])
	print("---", name_str, "---")
	type_info_root_name = find_str(name)
	type_info_root = toAddr(find_num_single(type_info_root_name)).add(-4)
	clearListing(type_info_root, type_info_root.add(8))
	createData(type_info_root, cxx_type_info_root)
	createLabel(type_info_root, name_str+"_type_info", True)
	
	vtbl_addr = toAddr(getLong(type_info_root) & 0xFFFFFFFF)
	createLabel(vtbl_addr, name_str+"_typeinfo_vtable", True)
	
	for x in find_num(type_info_root.getOffset()):
		mark_typeinfo(toAddr(x), name_str)
		
	for x in find_num(vtbl_addr.getOffset()):
		mark_typeinfo_vtbl_ref(toAddr(x), name_str)
		
	print(name_str, "@", type_info_root)


mark_typeinfo_root(b"St9type_info\0")
mark_typeinfo_root(b"8MafTimer\0")

#TODO: more roots
#TODO: remove old labels
#TODO: demangle names

