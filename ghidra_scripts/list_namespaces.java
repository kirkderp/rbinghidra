// List non-global, non-function namespaces found in the program's symbol table.
// Usage: <output_path>
// Always exits 0 and writes a valid JSON envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class list_namespaces extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.list_namespaces.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[list_namespaces] missing args; expected <output_path>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[list_namespaces] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("total_namespaces", 0);
        envelope.put("namespaces", new ArrayList<Map<String, Object>>());

        try {
            Map<String, Namespace> nsObjects = new LinkedHashMap<>();
            Map<String, Long> nsCounts = new LinkedHashMap<>();

            SymbolIterator symIt = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symIt.hasNext()) {
                Symbol sym = symIt.next();
                if (sym == null) {
                    continue;
                }
                Namespace ns;
                try {
                    ns = sym.getParentNamespace();
                } catch (Exception e) {
                    printerr("[list_namespaces] getParentNamespace failed: " + e.getMessage());
                    continue;
                }
                if (ns == null) {
                    continue;
                }
                if (ns.isGlobal()) {
                    continue;
                }
                if (ns instanceof Function) {
                    continue;
                }
                String fqn = ns.getName(true);
                if (!nsObjects.containsKey(fqn)) {
                    nsObjects.put(fqn, ns);
                    nsCounts.put(fqn, 0L);
                }
                nsCounts.put(fqn, nsCounts.get(fqn) + 1L);
            }

            List<Map<String, Object>> nsList = new ArrayList<>();
            for (Map.Entry<String, Namespace> entry : nsObjects.entrySet()) {
                String fqn = entry.getKey();
                Namespace ns = entry.getValue();
                long count = nsCounts.getOrDefault(fqn, 0L);

                String typeStr = classifyNamespace(ns);

                String parentStr = "";
                try {
                    Namespace parent = ns.getParentNamespace();
                    if (parent != null && !parent.isGlobal()) {
                        parentStr = parent.getName(true);
                    }
                } catch (Exception e) {
                    parentStr = "";
                }

                Map<String, Object> nsMap = new LinkedHashMap<>();
                nsMap.put("name", ns.getName());
                nsMap.put("full_name", fqn);
                nsMap.put("type", typeStr);
                nsMap.put("member_count", count);
                nsMap.put("parent", parentStr);
                nsList.add(nsMap);
            }

            nsList.sort(new Comparator<Map<String, Object>>() {
                @Override
                public int compare(Map<String, Object> a, Map<String, Object> b) {
                    long ca = (Long) a.get("member_count");
                    long cb = (Long) b.get("member_count");
                    return Long.compare(cb, ca);
                }
            });

            envelope.put("total_namespaces", (long) nsList.size());
            envelope.put("namespaces", nsList);
        } catch (Exception e) {
            printerr("[list_namespaces] unexpected error: " + e.getMessage());
        }

        writeOutput(outputPath, envelope);
        println("[list_namespaces] total_namespaces=" + envelope.get("total_namespaces") + " -> " + outputPath);
    }

    private String classifyNamespace(Namespace ns) {
        if (ns == null) {
            return "namespace";
        }
        String simpleName = ns.getClass().getSimpleName();
        if ("GhidraClass".equals(simpleName)) {
            return "class";
        }
        if ("Library".equals(simpleName)) {
            return "library";
        }
        return "namespace";
    }

    private void writeOutput(String outputPath, Map<String, Object> envelope) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
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
