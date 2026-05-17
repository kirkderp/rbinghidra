// Create a user-defined label at an address and write a JSON envelope to the output path.
// Usage: <output_path> <address> <label_name>
// address is a hex address string (e.g. "0x100003a40" or "100003a40").
// Always exits 0 and writes a valid envelope; errors populate address_error or label_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class create_label extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.create_label.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("[create_label] missing args; expected <output_path> <address> <label_name>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String addressArg = args[1];
        String labelName = args[2];

        if (currentProgram == null) {
            printerr("[create_label] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("address", addressArg);
        envelope.put("label_name", labelName);
        envelope.put("created_symbol", "");
        envelope.put("address_error", "");
        envelope.put("label_error", "");

        AddressFactory af = currentProgram.getAddressFactory();
        String stripped = addressArg;
        if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
            stripped = stripped.substring(2);
        }
        Address addr;
        try {
            addr = af.getAddress(stripped);
        } catch (Exception e) {
            envelope.put("address_error", "cannot parse address: " + addressArg);
            writeOutput(outputPath, envelope);
            println("[create_label] cannot parse address: " + addressArg);
            return;
        }
        if (addr == null) {
            envelope.put("address_error", "cannot parse address: " + addressArg);
            writeOutput(outputPath, envelope);
            println("[create_label] cannot parse address: " + addressArg);
            return;
        }

        int txId = currentProgram.startTransaction("rbinghidra: create label");
        boolean committed = false;
        try {
            SymbolTable st = currentProgram.getSymbolTable();
            Symbol sym = st.createLabel(addr, labelName, SourceType.USER_DEFINED);
            envelope.put("created_symbol", sym.getName());
            committed = true;
        } catch (Exception e) {
            envelope.put("label_error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        } finally {
            currentProgram.endTransaction(txId, committed);
        }

        writeOutput(outputPath, envelope);
        println("[create_label] label '" + labelName + "' at " + addressArg
            + " committed=" + committed);
    }

    private void writeOutput(String outputPath, Map<String, Object> envelope) throws IOException {
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
