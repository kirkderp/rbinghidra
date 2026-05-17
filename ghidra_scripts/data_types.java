// Query the program data type database and write a JSON envelope to the output path.
// Usage: <output_path> [query] [offset] [limit]
// query is an optional case-insensitive substring filter against data type names; empty = all.
// Results are paged and capped at 1000 entries per call.
// Always exits 0 and writes a valid envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
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

public class data_types extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.data_types.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[data_types] missing args; expected <output_path> [query] [offset] [limit]");
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
            printerr("[data_types] no program loaded");
            throw new IllegalStateException("no program");
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<Map<String, Object>> dtList = new ArrayList<>();
        int totalMatched = 0;
        Iterator<DataType> dtIt = dtm.getAllDataTypes();
        while (dtIt.hasNext()) {
            DataType dt = dtIt.next();
            String name = dt.getName();
            if (name == null) continue;
            if (!query.isEmpty() && !name.toLowerCase().contains(query.toLowerCase())) {
                continue;
            }
            int index = totalMatched;
            totalMatched++;
            if (index < offset) continue;
            if (dtList.size() >= limit) continue;
            Map<String, Object> dm = new LinkedHashMap<>();
            dm.put("name", name);
            dm.put("path", dt.getPathName() != null ? dt.getPathName() : "");
            dm.put("category", dt.getCategoryPath() != null ? dt.getCategoryPath().getPath() : "/");
            String simpleName = dt.getClass().getSimpleName();
            if (simpleName.endsWith("DataType")) {
                simpleName = simpleName.substring(0, simpleName.length() - "DataType".length());
            }
            dm.put("kind", simpleName);
            dm.put("size", dt.getLength());
            String desc = dt.getDescription();
            dm.put("description", desc != null ? desc : "");
            dtList.add(dm);
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("truncated", totalMatched > offset + dtList.size());
        envelope.put("data_types", dtList);

        writeOutput(outputPath, envelope);
        println("[data_types] query='" + query + "' matched=" + totalMatched + " returned=" + dtList.size());
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
