// Emit the artifacts the reverse-engineering pack promises:
//   decompiled/<addr>_<name>.c, callgraph.txt, strings_xrefs.txt, summary.txt
// Usage: analyzeHeadless <proj> <name> -import <bin> -scriptPath scripts/ghidra \
//          -postScript ReportArtifacts.java <absolute-output-dir>
// Ghidra scripts execute with the privileges of the user running Ghidra.
//@category ARTEX

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ReportArtifacts extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "ghidra-out").getAbsoluteFile();
        File decDir = new File(outDir, "decompiled");
        if (!decDir.exists() && !decDir.mkdirs()) {
            throw new RuntimeException("cannot create " + decDir);
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);

        PrintWriter cg = new PrintWriter(new File(outDir, "callgraph.txt"), "UTF-8");
        cg.println("# caller_addr\tcaller\tcallee_addr\tcallee");
        PrintWriter decIndex = new PrintWriter(new File(outDir, "decompiled_index.txt"), "UTF-8");
        decIndex.println("# addr\tname\tstatus\tfile");

        int total = 0;
        int ok = 0;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();
            total++;
            Address entry = f.getEntryPoint();

            Set<Function> callees = f.getCalledFunctions(monitor);
            for (Function c : callees) {
                cg.println(entry + "\t" + f.getName() + "\t" + c.getEntryPoint() + "\t" + c.getName());
            }

            String safe = f.getName().replaceAll("[^A-Za-z0-9_.-]", "_");
            if (safe.length() > 60) {
                safe = safe.substring(0, 60);
            }
            String fileName = entry + "_" + safe + ".c";
            File out = new File(decDir, fileName);

            String status;
            try {
                DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    String c = res.getDecompiledFunction().getC();
                    Files.write(out.toPath(), c.getBytes(StandardCharsets.UTF_8));
                    status = "decompiled";
                    ok++;
                } else {
                    status = "failed:" + (res == null ? "null" : res.getErrorMessage());
                    Files.write(out.toPath(), ("// decompile failed: " + status + "\n").getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                status = "error:" + e.getClass().getSimpleName();
                Files.write(out.toPath(), ("// decompile error: " + e + "\n").getBytes(StandardCharsets.UTF_8));
            }
            decIndex.println(entry + "\t" + f.getName() + "\t" + status + "\t" + out.getName());
        }
        cg.close();
        decIndex.close();
        ifc.dispose();

        // Strings and their cross-references.
        PrintWriter sx = new PrintWriter(new File(outDir, "strings_xrefs.txt"), "UTF-8");
        sx.println("# string_addr\tstring\txref_from\txref_function");
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        int stringCount = 0;
        while (di.hasNext() && !monitor.isCancelled()) {
            Data d = di.next();
            Object value;
            try {
                value = d.getValue();
            } catch (Exception e) {
                continue;
            }
            if (!(value instanceof String)) {
                continue;
            }
            String s = (String) value;
            if (s.length() < 4) {
                continue;
            }
            stringCount++;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
            if (!refs.hasNext()) {
                sx.println(d.getAddress() + "\t" + escape(s) + "\t-\t-");
            } else {
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    Function rf = fm.getFunctionContaining(r.getFromAddress());
                    sx.println(d.getAddress() + "\t" + escape(s) + "\t" + r.getFromAddress() + "\t"
                            + (rf == null ? "-" : rf.getName()));
                }
            }
        }
        sx.close();

        PrintWriter sum = new PrintWriter(new File(outDir, "summary.txt"), "UTF-8");
        sum.println("program=" + currentProgram.getName());
        sum.println("executable_path=" + currentProgram.getExecutablePath());
        sum.println("executable_sha256=" + sha256(currentProgram.getExecutablePath()));
        sum.println("executable_format=" + currentProgram.getExecutableFormat());
        sum.println("language=" + currentProgram.getLanguageID());
        sum.println("compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        sum.println("image_base=" + currentProgram.getImageBase());
        sum.println("function_count=" + total);
        sum.println("functions_decompiled=" + ok);
        sum.println("defined_strings_over_3_chars=" + stringCount);
        sum.println("ghidra_version=" + ghidra.framework.Application.getApplicationVersion());
        sum.println("ghidra_build=" + ghidra.framework.Application.getApplicationReleaseName());
        sum.close();

        println("ARTEX artifacts written to " + outDir
                + " functions=" + total + " decompiled=" + ok + " strings=" + stringCount);
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String sha256(String path) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = Files.readAllBytes(new File(path).toPath());
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }
}
