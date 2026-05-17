// Read raw bytes from the currently loaded program and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <address> [size]
// address is parsed via AddressFactory.getAddress after stripping a leading "0x"/"0X" prefix.
// size defaults to 32, is clamped to the hard cap 8192 (matching pyghidra_mcp). Zero-size reads are permitted.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class read_bytes extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.read_bytes.v0";
    private static final long DEFAULT_SIZE = 32L;
    private static final long MAX_SIZE = 8192L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[read_bytes] missing args; expected <output_path> <address> [size]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String rawAddress = args[1];
        long size = parseLong(args, 2, DEFAULT_SIZE);
        if (size < 0L) {
            size = 0L;
        }
        if (size > MAX_SIZE) {
            size = MAX_SIZE;
        }

        if (currentProgram == null) {
            printerr("[read_bytes] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("address", rawAddress);
        envelope.put("resolved_address", "");
        envelope.put("size", 0L);
        envelope.put("hex", "");
        envelope.put("ascii_preview", "");
        envelope.put("read_error", "");

        Address addr;
        try {
            addr = resolveInputAddress(rawAddress);
        } catch (Exception e) {
            envelope.put("read_error", "invalid address '" + rawAddress + "': " + e.getMessage());
            writeEnvelope(outputPath, envelope);
            return;
        }
        if (addr == null) {
            envelope.put("read_error", "invalid address '" + rawAddress + "'");
            writeEnvelope(outputPath, envelope);
            return;
        }
        envelope.put("resolved_address", addr.toString());

        int requested = (int) size;
        byte[] buf = new byte[requested];
        int read;
        try {
            Memory mem = currentProgram.getMemory();
            read = mem.getBytes(addr, buf);
        } catch (MemoryAccessException e) {
            envelope.put("read_error", "memory access failed at " + addr + ": " + e.getMessage());
            writeEnvelope(outputPath, envelope);
            return;
        }
        if (read < 0) {
            read = 0;
        }

        StringBuilder hex = new StringBuilder(read * 2);
        StringBuilder ascii = new StringBuilder(read);
        for (int i = 0; i < read; i++) {
            int b = buf[i] & 0xff;
            hex.append(String.format("%02x", b));
            if (b >= 0x20 && b <= 0x7e) {
                ascii.append((char) b);
            } else {
                ascii.append('.');
            }
        }

        envelope.put("size", (long) read);
        envelope.put("hex", hex.toString());
        envelope.put("ascii_preview", ascii.toString());

        writeEnvelope(outputPath, envelope);
        println("[read_bytes] read " + read + " bytes at " + addr + " (requested " + requested
            + ") to " + outputPath);
    }

    private Address resolveInputAddress(String raw) {
        AddressFactory af = currentProgram.getAddressFactory();
        String stripped = raw;
        if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
            stripped = stripped.substring(2);
        }
        return af.getAddress(stripped);
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
            printerr("[read_bytes] could not parse '" + raw + "' as long; using default " + defaultValue);
            return defaultValue;
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
