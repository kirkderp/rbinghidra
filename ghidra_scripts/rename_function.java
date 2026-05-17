// Rename a function and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <name_or_address> <new_name>
// name_or_address is parsed as an address first, then falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// Always exits 0 and writes a valid envelope; errors populate resolution_error or rename_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
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

public class rename_function extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.rename_function.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("[rename_function] missing args; expected <output_path> <name_or_address> <new_name>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
        String newName = args[2];

        if (currentProgram == null) {
            printerr("[rename_function] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("new_name", newName);
        envelope.put("old_name", "");
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("resolution_error", "");
        envelope.put("rename_error", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function fn;
        try {
            fn = resolveFunction(fm, query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            println("[rename_function] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        String oldName = safeFullName(fn);
        envelope.put("old_name", oldName);
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        int txId = currentProgram.startTransaction("rbinghidra: rename function");
        boolean committed = false;
        try {
            fn.setName(newName, SourceType.USER_DEFINED);
            committed = true;
        } catch (Exception e) {
            envelope.put("rename_error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        } finally {
            currentProgram.endTransaction(txId, committed);
        }

        envelope.put("function_name", safeFullName(fn));

        writeOutput(outputPath, envelope);
        println("[rename_function] renamed '" + oldName + "' -> '" + safeFullName(fn) + "' at "
            + envelope.get("address"));
    }

    private Function resolveFunction(FunctionManager fm, String nameOrAddress) throws ResolutionException {
        Address targetAddress = null;
        try {
            AddressFactory af = currentProgram.getAddressFactory();
            String stripped = nameOrAddress;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            targetAddress = af.getAddress(stripped);
        } catch (Exception e) {
            targetAddress = null;
        }
        if (targetAddress != null) {
            Function hit = fm.getFunctionAt(targetAddress);
            if (hit != null) {
                return hit;
            }
            hit = fm.getFunctionContaining(targetAddress);
            if (hit != null) {
                return hit;
            }
        }

        String nameLc = nameOrAddress.toLowerCase();
        List<Function> exactMatches = new ArrayList<>();
        List<Function> partialMatches = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function func = it.next();
            if (func == null) {
                continue;
            }
            String qualified;
            try {
                qualified = func.getName(true);
            } catch (Exception e) {
                continue;
            }
            if (qualified == null) {
                continue;
            }
            String qLc = qualified.toLowerCase();
            if (nameLc.equals(qLc)) {
                exactMatches.add(func);
            } else if (qLc.contains(nameLc)) {
                partialMatches.add(func);
            }
        }

        List<Function> picked = !exactMatches.isEmpty() ? exactMatches : partialMatches;
        if (picked.isEmpty()) {
            throw new ResolutionException("Function '" + nameOrAddress + "' not found.");
        }
        if (picked.size() > 1) {
            StringBuilder sb = new StringBuilder();
            sb.append("Ambiguous match for '").append(nameOrAddress).append("'. Matches: ");
            int shown = 0;
            for (Function f : picked) {
                if (shown > 0) {
                    sb.append(", ");
                }
                try {
                    sb.append(f.getName(true));
                } catch (Exception e) {
                    sb.append("?");
                }
                if (f.getEntryPoint() != null) {
                    sb.append(" @ ").append(f.getEntryPoint().toString());
                }
                shown++;
                if (shown >= 5 && picked.size() > shown) {
                    sb.append(" (+").append(picked.size() - shown).append(" more)");
                    break;
                }
            }
            throw new ResolutionException(sb.toString());
        }
        return picked.get(0);
    }

    private String safeFullName(Function func) {
        try {
            return func.getName(true);
        } catch (Exception e) {
            try {
                return func.getName();
            } catch (Exception e2) {
                return "";
            }
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

    private static class ResolutionException extends Exception {
        ResolutionException(String msg) {
            super(msg);
        }
    }
}
