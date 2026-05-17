// List exported symbols (entry points exposed by this binary) and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> [query] [offset] [limit]
// query is a literal substring applied case-insensitively as a partial match; empty or ".*" matches all.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
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
import java.util.regex.Pattern;

public class list_exports extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.list_exports.v0";
    private static final String DEFAULT_QUERY = ".*";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[list_exports] missing args; expected <output_path> [query] [offset] [limit]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String requestedQuery = args.length >= 2 && args[1] != null ? args[1] : "";
        String query = requestedQuery.isEmpty() || DEFAULT_QUERY.equals(requestedQuery)
            ? DEFAULT_QUERY
            : Pattern.quote(requestedQuery);
        long offset = parseLong(args, 2, DEFAULT_OFFSET);
        long limit = parseLong(args, 3, DEFAULT_LIMIT);
        if (offset < 0L) {
            offset = 0L;
        }
        if (limit < 0L) {
            limit = 0L;
        }
        if (limit > MAX_LIMIT) {
            limit = MAX_LIMIT;
        }

        if (currentProgram == null) {
            printerr("[list_exports] no program loaded");
            throw new IllegalStateException("no program");
        }

        Pattern pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);

        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> page = new ArrayList<>();

        while (it.hasNext()) {
            Symbol sym = it.next();
            try {
                if (sym == null) {
                    continue;
                }
                if (!sym.isExternalEntryPoint()) {
                    continue;
                }
                String name = sym.getName();
                if (name == null) {
                    continue;
                }
                if (!pattern.matcher(name).find()) {
                    continue;
                }
                long index = totalMatched;
                totalMatched++;
                if (index < offset) {
                    continue;
                }
                if ((long) page.size() >= limit) {
                    continue;
                }
                page.add(exportToMap(sym));
            } catch (Exception e) {
                errorCount++;
                printerr("[list_exports] error on symbol: " + e.getMessage());
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", requestedQuery);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("exports", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        println("[list_exports] matched " + totalMatched + " exports, returning "
            + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
    }

    private Map<String, Object> exportToMap(Symbol sym) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", sym.getName());
        entry.put("address", sym.getAddress() != null ? sym.getAddress().toString() : "");
        return entry;
    }

    private long parseLong(String[] args, int index, long defaultValue) {
        if (index >= args.length) {
            return defaultValue;
        }
        String raw = args[index];
        if (raw == null || raw.isEmpty()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            printerr("[list_exports] could not parse '" + raw + "' as long; using default " + defaultValue);
            return defaultValue;
        }
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
