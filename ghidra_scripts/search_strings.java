// List defined strings in the currently loaded program and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> [query] [offset] [limit]
// query is a Java regex applied case-insensitively as a partial match (Pattern.find()) against the string value, default ".*".
// Uses the string iterator available in the active Ghidra runtime.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class search_strings extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.search_strings.v0";
    private static final String DEFAULT_QUERY = ".*";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[search_strings] missing args; expected <output_path> [query] [offset] [limit]");
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
            printerr("[search_strings] no program loaded");
            throw new IllegalStateException("no program");
        }

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            printerr("[search_strings] invalid regex '" + query + "': " + e.getMessage());
            throw e;
        }

        Iterator<Data> dataIterator = openDefinedStringIterator();

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> page = new ArrayList<>();

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            try {
                if (data == null) {
                    continue;
                }
                Object rawValue = data.getValue();
                if (rawValue == null) {
                    continue;
                }
                String value = rawValue.toString();
                if (!pattern.matcher(value).find()) {
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
                page.add(stringToMap(data, value,
                    currentProgram.getFunctionManager(),
                    currentProgram.getReferenceManager()));
            } catch (Exception e) {
                errorCount++;
                printerr("[search_strings] error on string: " + e.getMessage());
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", requestedQuery);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("strings", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        println("[search_strings] matched " + totalMatched + " strings, returning "
            + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
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

    private Map<String, Object> stringToMap(Data data, String value,
            FunctionManager fm, ReferenceManager rm) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", data.getAddress() != null ? data.getAddress().toString() : "");
        entry.put("value", value);
        entry.put("length", (long) value.codePointCount(0, value.length()));
        String dataType = "";
        try {
            if (data.getDataType() != null) {
                dataType = data.getDataType().getName();
            }
        } catch (Exception e) {
            // leave empty
        }
        entry.put("data_type", dataType);
        try {
            entry.put("xref_count", (long) rm.getReferenceCountTo(data.getAddress()));
        } catch (Exception e) {
            entry.put("xref_count", 0L);
        }
        String containingFunction = "";
        try {
            if (data.getAddress() != null) {
                Function fn = fm.getFunctionContaining(data.getAddress());
                if (fn != null) {
                    containingFunction = fn.getName(true);
                }
            }
        } catch (Exception e) {
            // leave empty
        }
        entry.put("containing_function", containingFunction);
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
            printerr("[search_strings] could not parse '" + raw + "' as long; using default " + defaultValue);
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
