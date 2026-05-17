// Resolve a function's thunk chain to its ultimate target.
// Usage: <output_path> <name_or_address>
// name_or_address is parsed as an address first, then falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// Always exits 0 and writes a valid envelope; errors populate resolution_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
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

public class thunk_target extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.thunk_target.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[thunk_target] missing args; expected <output_path> <name_or_address>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];

        if (currentProgram == null) {
            printerr("[thunk_target] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("is_thunk", false);
        envelope.put("target_name", "");
        envelope.put("target_address", "");
        envelope.put("resolution_error", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function fn;
        try {
            fn = resolveFunction(fm, query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            println("[thunk_target] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        Function thunked = fn.getThunkedFunction(true);
        if (thunked == null) {
            envelope.put("is_thunk", false);
            envelope.put("target_name", "");
            envelope.put("target_address", "");
        } else {
            envelope.put("is_thunk", true);
            String targetName;
            try {
                targetName = thunked.getName(true);
            } catch (Exception e) {
                try {
                    targetName = thunked.getName();
                } catch (Exception e2) {
                    targetName = "";
                }
            }
            envelope.put("target_name", targetName);
            envelope.put("target_address", thunked.getEntryPoint() != null ? thunked.getEntryPoint().toString() : "");
        }

        writeOutput(outputPath, envelope);
        println("[thunk_target] query='" + query + "' is_thunk=" + envelope.get("is_thunk"));
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
