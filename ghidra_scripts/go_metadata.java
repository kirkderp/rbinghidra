// Heuristic Go metadata extractor for Ghidra projects.
// Usage: <output_path> [limit]
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class go_metadata extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.go_metadata.v0";
    private static final long DEFAULT_LIMIT = 100L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("missing args; expected <output_path> [limit]");
        }
        String outputPath = args[0];
        long limit = clamp(parseLong(args, 1, DEFAULT_LIMIT), 0L, MAX_LIMIT);

        ReferenceManager rm = currentProgram.getReferenceManager();
        List<Map<String, Object>> goVersions = new ArrayList<>();
        List<Map<String, Object>> modulePaths = new ArrayList<>();
        List<Map<String, Object>> packageStrings = new ArrayList<>();
        long stringsScanned = 0L;
        long errorCount = 0L;

        Iterator<Data> strings = openDefinedStringIterator();
        while (strings.hasNext()) {
            monitor.checkCancelled();
            Data data = strings.next();
            try {
                if (data == null || data.getAddress() == null || data.getValue() == null) {
                    continue;
                }
                stringsScanned++;
                String value = data.getValue().toString();
                if (value.isEmpty()) {
                    continue;
                }
                Map<String, Object> hit = stringHit(data, value, rm);
                if (looksLikeGoVersion(value) && goVersions.size() < limit) {
                    goVersions.add(hit);
                }
                if (looksLikeModulePath(value) && modulePaths.size() < limit) {
                    modulePaths.add(hit);
                }
                if (looksLikeGoPackageString(value) && packageStrings.size() < limit) {
                    packageStrings.add(hit);
                }
            } catch (Exception e) {
                errorCount++;
            }
        }

        List<Map<String, Object>> runtimeFunctions = new ArrayList<>();
        List<Map<String, Object>> mainCandidates = new ArrayList<>();
        long functionsScanned = 0L;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function fn = functions.next();
            if (fn == null || fn.isExternal()) {
                continue;
            }
            functionsScanned++;
            String name = fn.getName(true);
            if (name == null) {
                continue;
            }
            if (name.contains("runtime.") && runtimeFunctions.size() < limit) {
                runtimeFunctions.add(functionHit(fn));
            }
            if ((name.contains("main.") || name.endsWith(".main") || name.contains("main_main"))
                    && mainCandidates.size() < limit) {
                mainCandidates.add(functionHit(fn));
            }
        }

        boolean likelyGo = !goVersions.isEmpty()
            || packageStrings.stream().anyMatch(m -> String.valueOf(m.get("value")).contains("runtime."))
            || runtimeFunctions.size() >= 5;

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("likely_go", likelyGo);
        envelope.put("limit", limit);
        envelope.put("go_versions", goVersions);
        envelope.put("module_paths", modulePaths);
        envelope.put("package_strings", packageStrings);
        envelope.put("runtime_functions", runtimeFunctions);
        envelope.put("main_candidates", mainCandidates);
        envelope.put("total_strings_scanned", stringsScanned);
        envelope.put("total_functions_scanned", functionsScanned);
        envelope.put("error_count", errorCount);
        writeEnvelope(outputPath, envelope);
        println("[go_metadata] likely_go=" + likelyGo);
    }

    private boolean looksLikeGoVersion(String value) {
        return value.matches(".*go1\\.[0-9][A-Za-z0-9_.-]*.*") || value.contains("runtime.buildVersion");
    }

    private boolean looksLikeModulePath(String value) {
        return value.contains("go.mod")
            || value.contains("github.com/")
            || value.contains("golang.org/")
            || value.contains("google.golang.org/")
            || value.contains("gopkg.in/");
    }

    private boolean looksLikeGoPackageString(String value) {
        return value.contains("runtime.")
            || value.contains("net/http")
            || value.contains("crypto/")
            || value.contains("encoding/")
            || value.contains("syscall.")
            || value.contains("main.");
    }

    private Map<String, Object> stringHit(Data data, String value, ReferenceManager rm) {
        Map<String, Object> hit = new LinkedHashMap<>();
        hit.put("address", data.getAddress().toString());
        hit.put("value", value);
        hit.put("xref_count", (long) rm.getReferenceCountTo(data.getAddress()));
        return hit;
    }

    private Map<String, Object> functionHit(Function fn) {
        Map<String, Object> hit = new LinkedHashMap<>();
        hit.put("name", fn.getName(true));
        hit.put("address", fn.getEntryPoint().toString());
        return hit;
    }

    @SuppressWarnings("unchecked")
    private Iterator<Data> openDefinedStringIterator() throws Exception {
        try {
            Class<?> iterClass = Class.forName("ghidra.program.util.DefinedStringIterator");
            Method forProgram = iterClass.getMethod("forProgram", ghidra.program.model.listing.Program.class);
            Object iter = forProgram.invoke(null, currentProgram);
            return (Iterator<Data>) iter;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            Class<?> iterClass = Class.forName("ghidra.program.util.DefinedDataIterator");
            Method definedStrings = iterClass.getMethod("definedStrings", ghidra.program.model.listing.Program.class);
            Object iter = definedStrings.invoke(null, currentProgram);
            return (Iterator<Data>) iter;
        }
    }

    private long parseLong(String[] args, int index, long defaultValue) {
        if (index >= args.length || args[index] == null || args[index].isEmpty()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(args[index]);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private long clamp(long value, long min, long max) {
        return Math.max(min, Math.min(max, value));
    }

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            pw.write(gson.toJson(envelope));
        }
    }
}
