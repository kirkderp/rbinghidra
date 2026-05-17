// Create a function at an address and write a JSON envelope to the output path.
// Usage: <output_path> <address> <function_name>
// address is a hex address string (e.g. "0x100003a40" or "100003a40").
// Always exits 0 and writes a valid envelope; errors populate address_error or function_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class create_function extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.create_function.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("[create_function] missing args; expected <output_path> <address> <function_name>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String addressArg = args[1];
        String functionName = args[2];

        if (currentProgram == null) {
            printerr("[create_function] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("address", addressArg);
        envelope.put("function_name", functionName);
        envelope.put("created_function", "");
        envelope.put("existing_function", "");
        envelope.put("address_error", "");
        envelope.put("function_error", "");

        Address addr = parseTargetAddress(addressArg);
        if (addr == null) {
            envelope.put("address_error", "cannot parse address: " + addressArg);
            writeOutput(outputPath, envelope);
            println("[create_function] cannot parse address: " + addressArg);
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function existing = fm.getFunctionAt(addr);
        if (existing != null) {
            envelope.put("existing_function", safeFullName(existing));
            writeOutput(outputPath, envelope);
            println("[create_function] existing function at " + addr);
            return;
        }

        int txId = currentProgram.startTransaction("rbinghidra: create function");
        boolean committed = false;
        try {
            CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, addr, null, SourceType.USER_DEFINED);
            boolean applied = cmd.applyTo(currentProgram, monitor);
            if (!applied) {
                String status = cmd.getStatusMsg();
                envelope.put("function_error", status != null ? status : "CreateFunctionCmd failed");
            } else {
                Function created = fm.getFunctionAt(addr);
                if (created == null) {
                    envelope.put("function_error", "CreateFunctionCmd succeeded but no function exists at address");
                } else {
                    envelope.put("created_function", safeFullName(created));
                    committed = true;
                }
            }
        } catch (Exception e) {
            envelope.put("function_error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        } finally {
            currentProgram.endTransaction(txId, committed);
        }

        writeOutput(outputPath, envelope);
        println("[create_function] function '" + functionName + "' at " + addressArg
            + " committed=" + committed);
    }

    private Address parseTargetAddress(String addressArg) {
        try {
            AddressFactory af = currentProgram.getAddressFactory();
            String stripped = addressArg;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            return af.getAddress(stripped);
        } catch (Exception e) {
            return null;
        }
    }

    private String safeFullName(Function fn) {
        if (fn == null) {
            return "";
        }
        try {
            return fn.getName(true);
        } catch (Exception e) {
            return fn.getName();
        }
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
