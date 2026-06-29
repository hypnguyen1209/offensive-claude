// DecompileToC.java - Ghidra headless postScript: decompile every function to <program>.c
//
// Usage (driven by triage.py --decompile, or standalone):
//   $GHIDRA_HOME/support/analyzeHeadless /tmp/proj triage -import ./sample -overwrite \
//       -postScript DecompileToC.java -scriptPath /path/to/scripts/ghidra
//
// Tested against Ghidra 11.3 / 11.4.x. Writes one C file next to the project working dir.
// No external dependencies beyond the Ghidra runtime.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileToC extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        if (!dec.openProgram(currentProgram)) {
            printerr("Failed to open program in decompiler");
            return;
        }
        String outName = currentProgram.getName() + ".c";
        PrintWriter w = new PrintWriter(new FileWriter(outName));
        int ok = 0, fail = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            DecompileResults r = dec.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                w.println("// === " + f.getName() + " @ " + f.getEntryPoint() + " ===");
                w.println(r.getDecompiledFunction().getC());
                ok++;
            } else {
                fail++;
            }
        }
        w.close();
        dec.dispose();
        println("[DecompileToC] wrote " + outName + "  (ok=" + ok + " fail=" + fail + ")");
    }
}
