#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Create structs for hashed log entries and add the original message as a comment. These structs are passed to the logging function to print the hashed message
# Requires a file with one log entry per line, in the form of "<log_hash_decial>:<log_msg>"

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler

dtm = currentProgram.getDataTypeManager()
parser = CParser(dtm)

log_struct = parser.parse("""
struct qcom_msg {
    unsigned int hash;
    unsigned int unknown;
};
""")

transaction = dtm.startTransaction("Adding qcom_msg struct")
dtm.addDataType(log_struct, None)
dtm.endTransaction(transaction, True)


f = askFile("Select log hashes file", "Load")
with open(f.getPath()) as f:
    for line in f.readlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        try:
            hsh = int(parts[0])
        except:
            continue
        msg = ":".join(parts[1:])
        print "hash = " + hex(hsh) + ", msg=" + msg.replace("\n", "\\n")

        hsh_be_bytes = bytearray()
        while hsh:
            hsh_be_bytes.insert(0, hsh & 0xff)
            hsh >>= 8
        hsh_le_bytes = bytes(hsh_be_bytes)[::-1]

        msg_struct_start = find(currentProgram.getMinAddress(), hsh_le_bytes)
        if msg_struct_start is None:
            print "Log not found"
            continue

        print "Creating log @ " + str(msg_struct_start)
        setPreComment(msg_struct_start, msg)
        clearListing(msg_struct_start, msg_struct_start.add(8))
        createData(msg_struct_start, log_struct)

