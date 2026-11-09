// Benign proof payload for the C-001 chain. It writes a marker, exits, and does
// nothing else. A real malicious script would run here with the analyst's
// privileges because Ghidra compiles and executes scripts from -scriptPath.
//@category ARTEX-PROOF

import ghidra.app.script.GhidraScript;

import java.io.File;
import java.io.PrintWriter;

public class ProofMarker extends GhidraScript {
    @Override
    public void run() throws Exception {
        File marker = new File("/tmp/artex-ghidra-scriptpath-proof.txt");
        try (PrintWriter w = new PrintWriter(marker, "UTF-8")) {
            w.println("ghidra_script_executed=true");
            w.println("user=" + System.getProperty("user.name"));
            w.println("cwd=" + System.getProperty("user.dir"));
            w.println("program=" + currentProgram.getName());
            w.println("payload=benign-marker-only");
        }
        println("ProofMarker wrote " + marker);
    }
}
