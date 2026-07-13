# Annotate c++ classes by RTTI
#@author CUB3D
#@category Qualcomm
#@runtime Jython

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl, VariableStorage
from ghidra.program.model.data import VoidDataType, PointerDataType, UnsignedIntegerDataType, CharDataType
import subprocess

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


def clean_label_str(x):
        return x.replace("<", "_").replace(">", "_").replace(" ", "_").replace("(", "_").replace(")", "_")


def create_or_read_string(str_addr):
	try:
		name = createAsciiString(str_addr).getValue()
		if len(name) == 0:
			return None # pointer to zero data
		createLabel(typeinfo_base, name, True)
	except:
		name = getDataAt(str_addr)
		if name is None:
			print "BAD NAME @", str_addr
			return
		name = name.getValue()
		
		if ("unicode" not in str(type(name))) or len(name) == 0:
			return None # pointer to random data
        return name

def clear_and_set_lbl(addr, lbl, primary=True):
    print "set lbl", addr, lbl
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getSymbols(addr)
    
    for symbol in symbols:
        symbol_table.removeSymbolSpecial(symbol)

    createLabel(addr, clean_label_str(lbl), primary)


def is_addr_mapped(x):
	try:
		getLong(x)
		return True
	except:
		return False


def demangle(name):
    x = subprocess.check_output(['c++filt', "_Z" + name])
    # print(x)
    return x.strip()

def is_invalid_name(name):
	if name is None or len(name) == 0 or "\n" in name:
		return True
	return False

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

	clear_and_set_lbl(x, name + "_typeinfo", True)
	clear_and_set_lbl(x.add(4), name + "_vtable", True)
	i = 4
	while True:
		ptr = getLong(x.add(i)) & 0xFFFFFFFF
		if ptr == 0:
			break
		if not is_addr_mapped(toAddr(ptr)):
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

	if is_addr_mapped(toAddr(getLong(x.add(-4)) & 0xFFFFFFFF)):
		return
	#print(x)
	typeinfo_base = x.add(-8)
	
	str_addr = toAddr(getLong(typeinfo_base.add(4)) & 0xFFFFFFFF)
	if not is_addr_mapped(str_addr):
		return
	name = create_or_read_string(str_addr)
	if is_invalid_name(name):
		return

	demangled_name = demangle(name)
	clear_and_set_lbl(typeinfo_base, demangled_name, True)
	
	print("- " * indent, x, "=", name)
	
	clearListing(typeinfo_base, typeinfo_base.add(0xc))
	createData(typeinfo_base, cxx_type_info)
	
	for y in find_num(typeinfo_base.getOffset()):
		mark_typeinfo(toAddr(y), demangled_name, indent + 1)
		
		
	vtbl_addr = toAddr(getLong(typeinfo_base) & 0xFFFFFFFF)

	for x in find_num(vtbl_addr.getOffset()):
		mark_typeinfo_vtbl_ref(toAddr(x), demangled_name)

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
	if not is_addr_mapped(str_addr):
			return
	name = create_or_read_string(str_addr)
	if is_invalid_name(name):
			return
	demangled_name = demangle(name)
	clear_and_set_lbl(x, demangled_name + "_typeinfo", True)


	if (v1 == 0) or (v2 == 0) or (not is_addr_mapped(toAddr(v1))) or (not is_addr_mapped(toAddr(v2))):
		return
	
	if (v5 == 0) or (v4 == 0) or (not is_addr_mapped(toAddr(v5))) or (not is_addr_mapped(toAddr(v4))):
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
		mark_typeinfo_vtbl_ref(toAddr(x), demangled_name)

def mark_typeinfo_root(name):
	name_str = str(name[:-1])
        demangled_name = demangle(name_str)
	print("---", demangled_name, "---")
	type_info_root_name = find_str(name)
	type_info_root = toAddr(find_num_single(type_info_root_name)).add(-4)
	clearListing(type_info_root, type_info_root.add(8))
	createData(type_info_root, cxx_type_info_root)
	clear_and_set_lbl(type_info_root, demangled_name+"_type_info", True)
	
	vtbl_addr = toAddr(getLong(type_info_root) & 0xFFFFFFFF)
	clear_and_set_lbl(vtbl_addr, demangled_name+"_typeinfo_vtable", True)
	
	for x in find_num(type_info_root.getOffset()):
		mark_typeinfo(toAddr(x), demangled_name)
		
	for x in find_num(vtbl_addr.getOffset()):
		mark_typeinfo_vtbl_ref(toAddr(x), demangled_name)
		
	print(name_str, "@", type_info_root)


#mark_typeinfo_root(b"St9type_info\0")
mark_typeinfo_root(b"8MafTimer\0")



#TODO: more roots
#TODO: demangle names


