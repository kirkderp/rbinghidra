// Scan instruction immediates/constants and write a JSON envelope.
// Usage: <output_path> <mode: common|uses|range> [value] [min_value] [max_value] [include_small_values] [limit]
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class constants extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.constants.v0";
    private static final long DEFAULT_LIMIT = 100L;
    private static final long MAX_LIMIT = 1000L;
    private static final int MAX_SAMPLE_LOCATIONS = 5;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("missing args; expected <output_path> <mode> [value] [min_value] [max_value] [include_small_values] [limit]");
        }
        String outputPath = args[0];
        String mode = args[1] == null || args[1].isEmpty() ? "common" : args[1].toLowerCase();
        String valueText = arg(args, 2);
        String minText = arg(args, 3);
        String maxText = arg(args, 4);
        boolean includeSmall = Boolean.parseBoolean(arg(args, 5));
        long limit = clamp(parseLong(args, 6, DEFAULT_LIMIT), 0L, MAX_LIMIT);

        Long exactValue = valueText.isEmpty() ? null : parseInteger(valueText);
        Long minValue = minText.isEmpty() ? null : parseInteger(minText);
        Long maxValue = maxText.isEmpty() ? null : parseInteger(maxText);
        if ("uses".equals(mode) && exactValue == null) {
            throw new IllegalArgumentException("mode 'uses' requires value");
        }
        if ("range".equals(mode) && (minValue == null || maxValue == null)) {
            throw new IllegalArgumentException("mode 'range' requires min_value and max_value");
        }
        if (!"common".equals(mode) && !"uses".equals(mode) && !"range".equals(mode)) {
            throw new IllegalArgumentException("invalid mode: " + mode);
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Long, ConstantBucket> buckets = new LinkedHashMap<>();
        long instructionsScanned = 0L;
        long errorCount = 0L;

        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            instructionsScanned++;
            try {
                for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
                    for (Object obj : instruction.getOpObjects(opIndex)) {
                        if (!(obj instanceof Scalar)) {
                            continue;
                        }
                        long value = ((Scalar) obj).getValue();
                        if (!includeSmall && value >= 0L && value <= 255L) {
                            continue;
                        }
                        if ("uses".equals(mode) && value != exactValue.longValue()) {
                            continue;
                        }
                        if ("range".equals(mode) && (value < minValue.longValue() || value > maxValue.longValue())) {
                            continue;
                        }
                        ConstantBucket bucket = buckets.computeIfAbsent(value, ConstantBucket::new);
                        bucket.count++;
                        if (bucket.samples.size() < MAX_SAMPLE_LOCATIONS) {
                            bucket.samples.add(location(instruction, opIndex, fm));
                        }
                    }
                }
            } catch (Exception e) {
                errorCount++;
            }
        }

        List<ConstantBucket> sorted = new ArrayList<>(buckets.values());
        sorted.sort(Comparator.comparingLong((ConstantBucket b) -> b.count).reversed()
            .thenComparingLong(b -> b.value));

        List<Map<String, Object>> constants = new ArrayList<>();
        for (ConstantBucket bucket : sorted) {
            if (constants.size() >= limit) {
                break;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("value", Long.toString(bucket.value));
            entry.put("hex_value", "0x" + Long.toHexString(bucket.value));
            entry.put("count", bucket.count);
            entry.put("sample_locations", bucket.samples);
            constants.add(entry);
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("mode", mode);
        envelope.put("value", valueText);
        envelope.put("min_value", minText);
        envelope.put("max_value", maxText);
        envelope.put("include_small_values", includeSmall);
        envelope.put("limit", limit);
        envelope.put("instructions_scanned", instructionsScanned);
        envelope.put("total_matched", (long) buckets.size());
        envelope.put("truncated", buckets.size() > limit);
        envelope.put("error_count", errorCount);
        envelope.put("constants", constants);
        writeEnvelope(outputPath, envelope);
        println("[constants] mode=" + mode + " constants=" + buckets.size());
    }

    private Map<String, Object> location(Instruction instruction, int opIndex, FunctionManager fm) {
        Map<String, Object> loc = new LinkedHashMap<>();
        Address address = instruction.getAddress();
        Function function = fm.getFunctionContaining(address);
        loc.put("address", address.toString());
        loc.put("function_name", function != null ? function.getName(true) : "");
        loc.put("mnemonic", instruction.getMnemonicString());
        loc.put("operand_index", (long) opIndex);
        loc.put("disassembly", instruction.toString());
        return loc;
    }

    private static class ConstantBucket {
        long value;
        long count = 0L;
        List<Map<String, Object>> samples = new ArrayList<>();

        ConstantBucket(long value) {
            this.value = value;
        }
    }

    private String arg(String[] args, int index) {
        return index < args.length && args[index] != null ? args[index] : "";
    }

    private Long parseInteger(String raw) {
        String s = raw.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
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
