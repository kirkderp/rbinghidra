// Search decompiled function bodies and write matching snippets as JSON.
// Usage: <output_path> <query_regex> [offset] [limit] [context_lines] [max_functions]
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class search_decompilation extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.search_decompilation.v0";
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 200L;
    private static final long DEFAULT_CONTEXT_LINES = 2L;
    private static final long MAX_CONTEXT_LINES = 10L;
    private static final long DEFAULT_MAX_FUNCTIONS = 500L;
    private static final long MAX_MAX_FUNCTIONS = 5000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("missing args; expected <output_path> <query_regex> [offset] [limit] [context_lines] [max_functions]");
        }
        String outputPath = args[0];
        String query = args[1] == null ? "" : args[1];
        long offset = clampMin(parseLong(args, 2, 0L), 0L);
        long limit = clamp(parseLong(args, 3, DEFAULT_LIMIT), 0L, MAX_LIMIT);
        long contextLines = clamp(parseLong(args, 4, DEFAULT_CONTEXT_LINES), 0L, MAX_CONTEXT_LINES);
        long maxFunctions = clamp(parseLong(args, 5, DEFAULT_MAX_FUNCTIONS), 0L, MAX_MAX_FUNCTIONS);

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("invalid regex: " + e.getMessage(), e);
        }

        long totalMatched = 0L;
        long functionsScanned = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> hits = new ArrayList<>();

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && functionsScanned < maxFunctions) {
                monitor.checkCancelled();
                Function function = functions.next();
                if (function == null || function.isExternal()) {
                    continue;
                }
                functionsScanned++;
                try {
                    DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
                    if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
                        continue;
                    }
                    String text = results.getDecompiledFunction().getC();
                    if (text == null || text.isEmpty()) {
                        continue;
                    }
                    MatchSnippet snippet = findSnippet(text, pattern, (int) contextLines);
                    if (snippet == null) {
                        continue;
                    }
                    long index = totalMatched;
                    totalMatched++;
                    if (index < offset || hits.size() >= limit) {
                        continue;
                    }
                    Map<String, Object> hit = new LinkedHashMap<>();
                    hit.put("function_name", function.getName(true));
                    hit.put("address", function.getEntryPoint().toString());
                    hit.put("signature", function.getSignature().getPrototypeString());
                    hit.put("match_count", countMatches(text, pattern));
                    hit.put("first_line", (long) snippet.firstLine);
                    hit.put("snippet", snippet.lines);
                    hits.add(hit);
                } catch (Exception e) {
                    errorCount++;
                    printerr("[search_decompilation] " + function.getName(true) + ": " + e.getMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("context_lines", contextLines);
        envelope.put("max_functions", maxFunctions);
        envelope.put("total_matched", totalMatched);
        envelope.put("functions_scanned", functionsScanned);
        envelope.put("truncated", totalMatched > offset + limit);
        envelope.put("error_count", errorCount);
        envelope.put("hits", hits);
        writeEnvelope(outputPath, envelope);
        println("[search_decompilation] matched " + totalMatched + " functions");
    }

    private static class MatchSnippet {
        int firstLine;
        List<String> lines;
    }

    private MatchSnippet findSnippet(String text, Pattern pattern, int contextLines) {
        String[] lines = text.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            if (!pattern.matcher(lines[i]).find()) {
                continue;
            }
            int start = Math.max(0, i - contextLines);
            int end = Math.min(lines.length, i + contextLines + 1);
            MatchSnippet snippet = new MatchSnippet();
            snippet.firstLine = start + 1;
            snippet.lines = new ArrayList<>();
            for (int j = start; j < end; j++) {
                snippet.lines.add(lines[j]);
            }
            return snippet;
        }
        return null;
    }

    private long countMatches(String text, Pattern pattern) {
        long count = 0L;
        String[] lines = text.split("\\R", -1);
        for (String line : lines) {
            if (pattern.matcher(line).find()) {
                count++;
            }
        }
        return count;
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

    private long clampMin(long value, long min) {
        return Math.max(min, value);
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
