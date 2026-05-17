// Search for a byte pattern in the currently loaded program and write a JSON envelope.
// Usage: <output_path> <hex_pattern> [max_hits]
// hex_pattern must be an even-length hex string (e.g. "4889e5").
// max_hits defaults to 500 and is clamped to 500.
// Always exits 0 and writes a valid JSON envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
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

public class search_bytes extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.search_bytes.v0";
    private static final long DEFAULT_MAX_HITS = 500L;
    private static final long MAX_HITS_CAP = 500L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[search_bytes] missing args; expected <output_path> <hex_pattern> [max_hits]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String hexPattern = args[1];
        long maxHits = parseLong(args, 2, DEFAULT_MAX_HITS);
        if (maxHits < 1L) {
            maxHits = 1L;
        }
        if (maxHits > MAX_HITS_CAP) {
            maxHits = MAX_HITS_CAP;
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("hex_pattern", hexPattern);
        envelope.put("total_hits", 0L);
        envelope.put("truncated", false);
        envelope.put("hits", new ArrayList<>());
        envelope.put("error", "");

        try {
            if (currentProgram == null) {
                envelope.put("error", "no program loaded");
                writeEnvelope(outputPath, envelope);
                return;
            }

            byte[] pattern = parseHexPattern(hexPattern);

            Memory mem = currentProgram.getMemory();
            FunctionManager fm = currentProgram.getFunctionManager();
            Address start = currentProgram.getMinAddress();

            List<Map<String, Object>> hits = new ArrayList<>();
            boolean truncated = false;

            while (true) {
                Address hit = mem.findBytes(start, pattern, null, true, monitor);
                if (hit == null) {
                    break;
                }

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("address", hit.toString());
                Function fn = fm.getFunctionContaining(hit);
                entry.put("containing_function", fn != null ? fn.getName(true) : "");
                hits.add(entry);

                if (hits.size() >= (int) maxHits) {
                    truncated = true;
                    break;
                }

                start = hit.add(1);
            }

            envelope.put("total_hits", (long) hits.size());
            envelope.put("truncated", truncated);
            envelope.put("hits", hits);
        } catch (Exception e) {
            envelope.put("total_hits", 0L);
            envelope.put("truncated", false);
            envelope.put("hits", new ArrayList<>());
            envelope.put("error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        }

        writeEnvelope(outputPath, envelope);
        println("[search_bytes] pattern=" + hexPattern + " hits=" + envelope.get("total_hits")
            + " truncated=" + envelope.get("truncated") + " -> " + outputPath);
    }

    private byte[] parseHexPattern(String hex) throws IllegalArgumentException {
        if (hex == null || hex.isEmpty()) {
            throw new IllegalArgumentException("hex_pattern is empty");
        }
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("hex_pattern has odd length: " + hex);
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            String pair = hex.substring(i * 2, i * 2 + 2);
            result[i] = (byte) Integer.parseInt(pair, 16);
        }
        return result;
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
            printerr("[search_bytes] could not parse '" + raw + "' as long; using default " + fallback);
            return fallback;
        }
    }

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws IOException {
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
