/* Disassemble the loaded program linearly and emit (addr, bytes_hex, mnem)
 * tuples to a JSON file. Used by run_tests.py to compare Ghidra's SLEIGH
 * output against LLVM's llvm-objdump as ground truth.
 *
 * Args: <out_json>
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HexagonSleighDisasm extends GhidraScript {
    @Override public void run() throws Exception {
        String outPath = getScriptArgs()[0];

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        // Find the imported blob block (first non-system block)
        MemoryBlock blob = null;
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.isInitialized() && b.getStart().getOffset() < 0xE0000000L) {
                blob = b;
                break;
            }
        }
        if (blob == null) {
            Files.write(Paths.get(outPath),
                "{\"instructions\": [], \"error\": \"no blob block\"}".getBytes());
            return;
        }

        // Disassemble the entire blob
        Address start = blob.getStart();
        Address end   = blob.getEnd();
        DisassembleCommand cmd = new DisassembleCommand(start, null, false);
        cmd.applyTo(currentProgram, monitor);

        StringBuilder sb = new StringBuilder("{\"instructions\":[");
        boolean first = true;
        long bad = 0;
        InstructionIterator it = listing.getInstructions(start, true);
        while (it.hasNext()) {
            Instruction inst = it.next();
            if (inst.getAddress().getOffset() > end.getOffset()) break;
            byte[] bytes = inst.getBytes();
            String hex = bytesToHex(bytes);
            String mnem = inst.toString();
            if (!first) sb.append(",");
            first = false;
            sb.append("\n  {\"addr\":").append(inst.getAddress().getOffset())
              .append(",\"bytes\":\"").append(hex)
              .append("\",\"mnem\":").append(jsonStr(mnem)).append("}");
        }
        sb.append("\n]}\n");
        Files.write(Paths.get(outPath), sb.toString().getBytes());
        println("disasm wrote " + outPath);
    }

    private static String bytesToHex(byte[] bs) {
        StringBuilder b = new StringBuilder(bs.length * 2);
        for (byte x : bs) b.append(String.format("%02x", x & 0xff));
        return b.toString();
    }

    private static String jsonStr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': b.append("\\\\"); break;
                case '"':  b.append("\\\""); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        b.append("\"");
        return b.toString();
    }
}
