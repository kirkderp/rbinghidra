// List imported symbols (external symbols this binary depends on) and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> [query] [offset] [limit]
// query is a Java regex applied case-insensitively as a partial match (Pattern.find()), default ".*".
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.ReferenceManager;
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
import java.util.regex.PatternSyntaxException;

public class list_imports extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.list_imports.v0";
    private static final String DEFAULT_QUERY = ".*";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[list_imports] missing args; expected <output_path> [query] [offset] [limit]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String requestedQuery = args.length >= 2 && args[1] != null ? args[1] : "";
        String query = requestedQuery.isEmpty() ? DEFAULT_QUERY : requestedQuery;
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
            printerr("[list_imports] no program loaded");
            throw new IllegalStateException("no program");
        }

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            printerr("[list_imports] invalid regex '" + query + "': " + e.getMessage());
            throw e;
        }

        SymbolTable table = currentProgram.getSymbolTable();
        SymbolIterator it = table.getExternalSymbols();

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> page = new ArrayList<>();

        while (it.hasNext()) {
            Symbol sym = it.next();
            try {
                if (sym == null) {
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
                page.add(importToMap(sym, currentProgram.getReferenceManager()));
            } catch (Exception e) {
                errorCount++;
                printerr("[list_imports] error on symbol: " + e.getMessage());
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", requestedQuery);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("imports", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        println("[list_imports] matched " + totalMatched + " imports, returning "
            + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
    }

    private Map<String, Object> importToMap(Symbol sym, ReferenceManager rm) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", sym.getName());
        entry.put("address", sym.getAddress() != null ? sym.getAddress().toString() : "");
        String library = "";
        if (sym.getParentNamespace() != null) {
            String full = sym.getParentNamespace().getName(true);
            library = full != null ? full : "";
        }
        entry.put("library", library);
        try {
            entry.put("xref_count", (long) rm.getReferenceCountTo(sym.getAddress()));
        } catch (Exception e) {
            entry.put("xref_count", 0L);
        }
        return entry;
    }

    private long parseLong(String[] args, int index, long fallback) {
        if (index >= args.length) {
            return fallback;
        }
        String raw = args[index];
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            printerr("[list_imports] could not parse '" + raw + "' as long; using default " + fallback);
            return fallback;
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
