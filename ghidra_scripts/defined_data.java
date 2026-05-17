// List defined non-string data items in the currently loaded program and write a JSON envelope.
// Usage: <output_path> [query] [offset] [limit]
// query is a Java regex applied case-insensitively as a partial match (Pattern.find()) against
// the label OR data_type_name. Default ".*".
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
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

public class defined_data extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.defined_data.v0";
    private static final String DEFAULT_QUERY = ".*";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[defined_data] missing args; expected <output_path> [query] [offset] [limit]");
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
            printerr("[defined_data] no program loaded");
            throw new IllegalStateException("no program");
        }

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            printerr("[defined_data] invalid regex '" + query + "': " + e.getMessage());
            throw e;
        }

        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> page = new ArrayList<>();

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            try {
                if (data == null) {
                    continue;
                }
                if (data.getDataType() == null) {
                    continue;
                }
                if (data.getDataType() instanceof AbstractStringDataType) {
                    continue;
                }

                String label = "";
                try {
                    Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(data.getAddress());
                    if (sym != null) {
                        label = sym.getName(true);
                    }
                } catch (Exception e) {
                    // leave empty
                }

                String dataTypeName = data.getDataType().getName();

                if (!pattern.matcher(label).find() && !pattern.matcher(dataTypeName).find()) {
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

                page.add(dataToMap(data, label, dataTypeName, fm, rm));
            } catch (Exception e) {
                errorCount++;
                printerr("[defined_data] error on data item: " + e.getMessage());
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", requestedQuery);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("data", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        println("[defined_data] matched " + totalMatched + " items, returning "
            + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
    }

    private Map<String, Object> dataToMap(Data data, String label, String dataTypeName,
            FunctionManager fm, ReferenceManager rm) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", data.getAddress() != null ? data.getAddress().toString() : "");
        entry.put("label", label);
        entry.put("data_type_name", dataTypeName);
        entry.put("size", (long) data.getLength());

        String value = "";
        try {
            Object rawValue = data.getValue();
            if (rawValue != null) {
                String raw = rawValue.toString();
                value = raw.length() > 200 ? raw.substring(0, 200) : raw;
            }
        } catch (Exception e) {
            // leave empty
        }
        entry.put("value", value);

        long xrefCount = 0L;
        try {
            xrefCount = (long) rm.getReferenceCountTo(data.getAddress());
        } catch (Exception e) {
            // leave 0
        }
        entry.put("xref_count", xrefCount);

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
            printerr("[defined_data] could not parse '" + raw + "' as long; using default " + defaultValue);
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
