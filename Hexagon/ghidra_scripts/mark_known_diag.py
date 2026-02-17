#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Create structs for known diag handler tables

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType

# Makes this much slower
VERBOSE = False

dtm = currentProgram.getDataTypeManager()
parser = CParser(dtm)

diag_ent = parser.parse("""
struct qcom_diag_ent {
    ushort id;
    ushort id_again;
    void* handler;
};
""")

known_diags = [
    ("(\\x00\\x00){2}.{4}(\\x7c\\x00){2}", 3, "DIAG_tools"),
    
    ("(\\x0c\\x00){2}.{4}(\\x0f\\x00){2}", 4, "DIAG_wms_0"),
    ("(\\x00\\x00){2}.{4}(\\x01\\x00){2}.{4}(\\x02\\x00){2}.{4}(\\x03\\x00){2}.{4}(\\x04\\x00){2}.{4}(\\x05\\x00){2}.{4}(\\x06\\x00){2}.{4}(\\x07\\x00){2}.{4}(\\x08\\x00){2}.{4}(\\x09\\x00){2}.{4}(\\x15\\x00){2}", 11, "DIAG_wms_1"),
    
    ("(\\x18\\x00){2}.{4}(\\x19\\x00){2}.{4}(\\x1b\\x00){2}", 13, "DIAG_cm_0"),
    
    ("(\\xf1\\x00){2}.{4}(\\xf2\\x00){2}", 9, "DIAG_tcxo_0"),
    
    ("(\\x00\\xfa){2}.{4}(\\x02\\xfa){2}", 86, "DIAG_uim"),
    ("(\\x00\\x00){2}.{4}(\\x09\\x00){2}.{4}(\\x0a\\x00){2}", 4, "DIAG_umts"),
]

transaction = dtm.startTransaction("Adding qcom_diag_ent struct")
dtm.addDataType(diag_ent, None)
dtm.endTransaction(transaction, True)

start_address = currentProgram.getMinAddress()

for (pattern, size, name) in known_diags:
    pos = findBytes(start_address, pattern, 1, 4)[0]
    print "Found", name, "@", pos
    clearListing(pos, pos.add(8 * (size - 1)+4))
    createLabel(pos, name, True)
    array_datatype = ArrayDataType(diag_ent, size)
    createData(pos, array_datatype)
