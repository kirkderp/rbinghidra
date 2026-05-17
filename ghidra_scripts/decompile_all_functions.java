// Decompile all functions in the program and write a JSON array to the path passed as the first script argument.
// Usage: <output_path>
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

public class decompile_all_functions extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompile_all_functions.v0";
    private static final int DECOMPILE_TIMEOUT_SECONDS = 45;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[decompile_all_functions] missing args; expected <output_path>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[decompile_all_functions] no program loaded");
            throw new IllegalStateException("no program");
        }

        DecompInterface iface = new DecompInterface();
        try {
            iface.openProgram(currentProgram);
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            List<Map<String, Object>> functions = new ArrayList<>();
            int total = 0;
            int errors = 0;

            while (it.hasNext() && !monitor.isCancelled()) {
                Function fn = it.next();
                total++;
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", fn.getName());
                entry.put("address", fn.getEntryPoint().toString());
                entry.put("signature", fn.getSignature().getPrototypeString());

                DecompileResults results = iface.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
                String pseudocode = "";
                String decompileError = "";
                if (results != null && results.decompileCompleted()) {
                    DecompiledFunction df = results.getDecompiledFunction();
                    if (df != null && df.getC() != null) {
                        pseudocode = df.getC();
                    }
                } else if (results != null) {
                    decompileError = results.getErrorMessage();
                    if (decompileError == null) {
                        decompileError = "";
                    }
                    errors++;
                }

                entry.put("pseudocode", pseudocode);
                entry.put("callers", collectNames(fn.getCallingFunctions(monitor)));
                entry.put("callees", collectNames(fn.getCalledFunctions(monitor)));
                entry.put("decompile_error", decompileError);
                functions.add(entry);
            }

            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("schema", SCHEMA);
            envelope.put("program_name", currentProgram.getName());
            envelope.put("program_path", currentProgram.getExecutablePath());
            envelope.put("function_count", total);
            envelope.put("error_count", errors);
            envelope.put("functions", functions);

            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            String json = gson.toJson(envelope);
            writeOutput(outputPath, json);
            println("[decompile_all_functions] wrote " + total + " functions (" + errors + " errors) to " + outputPath);
        } finally {
            try {
                iface.dispose();
            } catch (Exception e) {
                printerr("[decompile_all_functions] iface.dispose threw: " + e.getMessage());
            }
        }
    }

    private List<String> collectNames(java.util.Set<Function> fns) {
        java.util.Set<String> sorted = new TreeSet<>();
        if (fns != null) {
            for (Function f : fns) {
                if (f != null && f.getName() != null) {
                    sorted.add(f.getName());
                }
            }
        }
        return new ArrayList<>(sorted);
    }

    private void writeOutput(String outputPath, String json) throws IOException {
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            pw.write(json);
        }
    }
}
