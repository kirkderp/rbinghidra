// Return matching strings with xrefs and short decompiler snippets from referrer functions.
// Usage: <output_path> <query_or_address> [string_limit] [xref_limit] [snippet_chars]
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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

public class stringcontext extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.string_context.v0";
    private static final long DEFAULT_STRING_LIMIT = 5L;
    private static final long DEFAULT_XREF_LIMIT = 10L;
    private static final long DEFAULT_SNIPPET_CHARS = 1200L;
    private static final long MAX_STRING_LIMIT = 25L;
    private static final long MAX_XREF_LIMIT = 50L;
    private static final long MAX_SNIPPET_CHARS = 4000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("missing args; expected <output_path> <query_or_address> [string_limit] [xref_limit] [snippet_chars]");
        }
        String outputPath = args[0];
        String query = args[1] == null ? "" : args[1];
        long stringLimit = clamp(parseLong(args, 2, DEFAULT_STRING_LIMIT), 0L, MAX_STRING_LIMIT);
        long xrefLimit = clamp(parseLong(args, 3, DEFAULT_XREF_LIMIT), 0L, MAX_XREF_LIMIT);
        long snippetChars = clamp(parseLong(args, 4, DEFAULT_SNIPPET_CHARS), 0L, MAX_SNIPPET_CHARS);

        Address requestedAddress = parseQueryAddress(query);
        Pattern pattern = requestedAddress == null ? Pattern.compile(Pattern.quote(query), Pattern.CASE_INSENSITIVE) : null;

        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> strings = new ArrayList<>();
        try {
            Iterator<Data> dataIterator = openDefinedStringIterator();
            while (dataIterator.hasNext()) {
                monitor.checkCancelled();
                Data data = dataIterator.next();
                if (data == null || data.getAddress() == null) {
                    continue;
                }
                Object raw = data.getValue();
                String value = raw == null ? "" : raw.toString();
                boolean matched = requestedAddress != null
                    ? data.getAddress().equals(requestedAddress)
                    : pattern.matcher(value).find();
                if (!matched) {
                    continue;
                }
                totalMatched++;
                if (strings.size() >= stringLimit) {
                    continue;
                }
                try {
                    strings.add(stringEntry(data, value, rm, fm, decompiler, xrefLimit, snippetChars));
                } catch (Exception e) {
                    errorCount++;
                    printerr("[string_context] " + data.getAddress() + ": " + e.getMessage());
                }
            }
        } finally {
            decompiler.dispose();
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("string_limit", stringLimit);
        envelope.put("xref_limit", xrefLimit);
        envelope.put("snippet_chars", snippetChars);
        envelope.put("total_strings_matched", totalMatched);
        envelope.put("truncated", totalMatched > stringLimit);
        envelope.put("error_count", errorCount);
        envelope.put("strings", strings);
        writeEnvelope(outputPath, envelope);
        println("[string_context] matched " + totalMatched + " strings");
    }

    private Map<String, Object> stringEntry(Data data, String value, ReferenceManager rm,
            FunctionManager fm, DecompInterface decompiler, long xrefLimit, long snippetChars) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", data.getAddress().toString());
        entry.put("value", value);
        entry.put("length", (long) value.codePointCount(0, value.length()));
        entry.put("data_type", data.getDataType() != null ? data.getDataType().getName() : "");
        long xrefCount = rm.getReferenceCountTo(data.getAddress());
        entry.put("xref_count", xrefCount);

        List<Map<String, Object>> xrefs = new ArrayList<>();
        ReferenceIterator refs = rm.getReferencesTo(data.getAddress());
        while (refs.hasNext() && xrefs.size() < xrefLimit) {
            Reference ref = refs.next();
            if (ref == null) {
                continue;
            }
            Function fn = fm.getFunctionContaining(ref.getFromAddress());
            Map<String, Object> xref = new LinkedHashMap<>();
            xref.put("from_address", ref.getFromAddress().toString());
            xref.put("ref_type", ref.getReferenceType().toString());
            xref.put("function_name", fn != null ? fn.getName(true) : "");
            xref.put("function_address", fn != null ? fn.getEntryPoint().toString() : "");
            xref.put("decompile_snippet", fn != null ? decompileSnippet(decompiler, fn, value, data.getAddress().toString(), (int) snippetChars) : "");
            xrefs.add(xref);
        }
        entry.put("xrefs_returned", (long) xrefs.size());
        entry.put("xrefs", xrefs);
        return entry;
    }

    private String decompileSnippet(DecompInterface decompiler, Function fn, String value, String address, int maxChars) {
        if (maxChars <= 0) {
            return "";
        }
        try {
            DecompileResults results = decompiler.decompileFunction(fn, 30, monitor);
            if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
                return "";
            }
            String text = results.getDecompiledFunction().getC();
            if (text == null) {
                return "";
            }
            String needle = value.length() > 0 ? value : address;
            int idx = text.toLowerCase().indexOf(needle.toLowerCase());
            if (idx < 0) {
                idx = text.toLowerCase().indexOf(address.toLowerCase());
            }
            if (idx < 0) {
                return abbreviate(text, maxChars);
            }
            int start = Math.max(0, idx - maxChars / 3);
            int end = Math.min(text.length(), start + maxChars);
            return text.substring(start, end);
        } catch (Exception e) {
            return "";
        }
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

    private Address parseQueryAddress(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        try {
            String stripped = raw.startsWith("0x") || raw.startsWith("0X") ? raw.substring(2) : raw;
            return currentProgram.getAddressFactory().getAddress(stripped);
        } catch (Exception e) {
            return null;
        }
    }

    private String abbreviate(String text, int maxChars) {
        return text.length() <= maxChars ? text : text.substring(0, maxChars);
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
