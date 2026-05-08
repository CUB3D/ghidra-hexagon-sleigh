/* Decompile a single named function from the loaded program and write
 * the result to a JSON file. Used by run_behavioral.py to validate
 * SLEIGH semantic fixes via decompiled-output substring assertions.
 *
 * Args: <out_json> <function_name>
 *
 * Output JSON shape:
 *   { "function": "<name>", "found": true|false,
 *     "address": "0x...", "decomp": "..." }
 */
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.nio.file.Files;
import java.nio.file.Paths;

public class BehavioralDecomp extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[0];
        String fnName  = args[1];

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st     = currentProgram.getSymbolTable();

        Function target = null;
        // Try by name lookup
        SymbolIterator it = st.getSymbols(fnName);
        while (it.hasNext()) {
            Symbol s = it.next();
            Function f = fm.getFunctionAt(s.getAddress());
            if (f != null) {
                target = f;
                break;
            }
        }
        // Fallback: first non-thunk function defined in a code block
        if (target == null) {
            for (Function f : fm.getFunctions(true)) {
                if (!f.isThunk() && !f.isExternal()) {
                    target = f;
                    break;
                }
            }
        }

        StringBuilder out = new StringBuilder("{");
        if (target == null) {
            out.append("\"function\":").append(jsonStr(fnName))
               .append(",\"found\":false}");
        } else {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            DecompileResults res = decomp.decompileFunction(target, 90, monitor);
            String c = "";
            if (res != null && res.getDecompiledFunction() != null) {
                c = res.getDecompiledFunction().getC();
            }
            out.append("\"function\":").append(jsonStr(target.getName()))
               .append(",\"found\":true")
               .append(",\"address\":\"").append(target.getEntryPoint().toString()).append("\"")
               .append(",\"decomp\":").append(jsonStr(c))
               .append("}");
        }
        Files.write(Paths.get(outPath), out.toString().getBytes());
        println("decomp wrote " + outPath);
    }

    private static String jsonStr(String s) {
        if (s == null) return "null";
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
