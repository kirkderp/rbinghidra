// Search symbols by name substring and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <query> [offset] [limit]
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

public class search_symbols extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.search_symbols.v0";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[search_symbols] missing args; expected <output_path> <query> [offset] [limit]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
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
            printerr("[search_symbols] no program loaded");
            throw new IllegalStateException("no program");
        }

        String needle = query.toLowerCase();
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
                String name = sym.getName();
                if (name == null) {
                    continue;
                }
                if (!name.toLowerCase().contains(needle)) {
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
                page.add(symbolToMap(sym));
            } catch (Exception e) {
                errorCount++;
                printerr("[search_symbols] error on symbol: " + e.getMessage());
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("symbols", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        println("[search_symbols] matched " + totalMatched + " symbols, returning "
            + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
    }

    private Map<String, Object> symbolToMap(Symbol sym) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", sym.getName());
        entry.put("address", sym.getAddress() != null ? sym.getAddress().toString() : "");
        entry.put("type", sym.getSymbolType() != null ? sym.getSymbolType().toString() : "");
        String namespace = "";
        if (sym.getParentNamespace() != null) {
            String full = sym.getParentNamespace().getName(true);
            namespace = full != null ? full : "";
        }
        entry.put("namespace", namespace);
        entry.put("source", sym.getSource() != null ? sym.getSource().toString() : "");
        entry.put("refcount", sym.getReferenceCount());
        entry.put("external", sym.isExternal());
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
            printerr("[search_symbols] could not parse '" + raw + "' as long; using default " + fallback);
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
