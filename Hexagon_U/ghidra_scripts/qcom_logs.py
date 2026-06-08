#@author CUB3D
#@category Qualcomm
#@runtime Jython

# Create structs for hashed log entries and add the original message as a comment. These structs are passed to the logging function to print the hashed message
# Requires a file with one log entry per line, in the form of "<log_hash_decial>:<log_msg>"

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler

# Makes this much slower
VERBOSE = False

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

start_address = currentProgram.getMinAddress()

f = askFile("Select log hashes file", "Load")
with open(f.getPath()) as f:
    lines = f.readlines()
    num_lines = len(lines)
    monitor.initialize(num_lines, "Adding logs")
    for idx,line in enumerate(lines):
        monitor.incrementProgress()
        parts = line.split(":")
        if len(parts) < 2:
            continue
        try:
            hsh = int(parts[0])
        except:
            continue
        msg = ":".join(parts[1:])
        print str(idx) + "/" + str(num_lines) + ", hash = " + hex(hsh) + ", msg=" + msg.replace("\n", "\\n")

        # Convert hash to LE bytestring
        hsh_le_bytes = ""
        while hsh:
            hsh_le_bytes += ("\\x" +("00"+ hex(int(hsh & 0xFF))[2:])[-2:])
            hsh >>= 8
        
        msg_struct_start = findBytes(start_address, hsh_le_bytes, 1, 4)
        if len(msg_struct_start) == 0:
            if VERBOSE:
                print "Log not found"
            continue
        msg_struct_start = msg_struct_start[0]  

        print "Creating log @ " + str(msg_struct_start)
        clearListing(msg_struct_start, msg_struct_start.add(8))
        setPreComment(msg_struct_start, msg)
        createData(msg_struct_start, log_struct)

