// List named constants (equates) defined in the binary and write a JSON envelope to the output path.
// Usage: <output_path> [query] [offset] [limit]
// query is an optional case-insensitive substring filter against equate names; empty = all.
// Always exits 0 and writes a valid envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class equates extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.equates.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[equates] missing args; expected <output_path> [query] [offset] [limit]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args.length >= 2 ? args[1].trim() : "";
        int offset = parseInt(args, 2, 0);
        int limit = parseInt(args, 3, 500);
        if (offset < 0) offset = 0;
        if (limit < 0) limit = 0;
        if (limit > 1000) limit = 1000;

        if (currentProgram == null) {
            printerr("[equates] no program loaded");
            throw new IllegalStateException("no program");
        }

        EquateTable et = currentProgram.getEquateTable();
        List<Map<String, Object>> equateList = new ArrayList<>();
        int totalMatched = 0;
        Iterator<Equate> eqIt = et.getEquates();
        while (eqIt.hasNext()) {
            Equate eq = eqIt.next();
            String name = eq.getName();
            if (!query.isEmpty() && !name.toLowerCase().contains(query.toLowerCase())) {
                continue;
            }
            int index = totalMatched;
            totalMatched++;
            if (index < offset) continue;
            if (equateList.size() >= limit) continue;
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("name", name);
            em.put("value_hex", "0x" + Long.toHexString(eq.getValue()));
            em.put("value_dec", eq.getValue());
            em.put("display_name", eq.getDisplayName());
            List<Map<String, Object>> refs = new ArrayList<>();
            try {
                for (EquateReference ref : eq.getReferences()) {
                    Map<String, Object> rm = new LinkedHashMap<>();
                    rm.put("address", ref.getAddress().toString());
                    rm.put("op_index", ref.getOpIndex());
                    refs.add(rm);
                }
            } catch (Exception e) {
                // references unavailable; continue with empty list
            }
            em.put("reference_count", refs.size());
            em.put("references", refs);
            equateList.add(em);
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("truncated", totalMatched > offset + equateList.size());
        envelope.put("equates", equateList);

        writeOutput(outputPath, envelope);
        println("[equates] query='" + query + "' matched=" + totalMatched);
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

    private int parseInt(String[] args, int index, int defaultValue) {
        if (args.length <= index || args[index] == null || args[index].trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(args[index].trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
