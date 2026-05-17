// Decompile a single function and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <name_or_address> [simplification_style]
// name_or_address is parsed as an address first (AddressFactory.getAddress after stripping a
// leading 0x/0X prefix, mirroring callgraph.java/cfg.java). On address-path failure it falls back
// to case-insensitive exact-then-partial match against the fully-qualified function name
// (Function.getName(true)).
// simplification_style defaults to "decompile". Supported values mirror Ghidra's
// DecompInterface.setSimplificationStyle: decompile, normalize, register, firstpass, paramid.
// Always exits 0 and writes a valid envelope; lookup failures populate resolution_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
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
import java.util.Set;
import java.util.TreeSet;

public class decompile_function extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompile_function.v0";
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[decompile_function] missing args; expected <output_path> <name_or_address> [simplification_style]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;

        if (currentProgram == null) {
            printerr("[decompile_function] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("signature", "");
        envelope.put("decompiler_signature", "");
        envelope.put("pseudocode", "");
        envelope.put("callers", new ArrayList<String>());
        envelope.put("callees", new ArrayList<String>());
        envelope.put("caller_details", new ArrayList<Map<String, Object>>());
        envelope.put("callee_details", new ArrayList<Map<String, Object>>());
        envelope.put("basic_block_count", 0);
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function fn;
        try {
            fn = resolveFunction(fm, query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            println("[decompile_function] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");
        try {
            envelope.put("signature", fn.getSignature().getPrototypeString());
        } catch (Exception e) {
            envelope.put("signature", "");
        }
        envelope.put("callers", collectNames(fn.getCallingFunctions(monitor)));
        envelope.put("callees", collectNames(fn.getCalledFunctions(monitor)));
        envelope.put("caller_details", collectDetails(fn.getCallingFunctions(monitor)));
        envelope.put("callee_details", collectDetails(fn.getCalledFunctions(monitor)));

        DecompInterface iface = new DecompInterface();
        try {
            iface.setSimplificationStyle(simplificationStyle);
            iface.toggleSyntaxTree(true);
            iface.toggleCCode(true);
            iface.openProgram(currentProgram);
            DecompileResults results = iface.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
            String pseudocode = "";
            String decompilerSignature = "";
            String decompileError = "";
            boolean decompileCompleted = false;
            boolean decompileValid = false;
            boolean isTimedOut = false;
            boolean isCancelled = false;
            boolean failedToStart = false;
            int basicBlockCount = 0;
            if (results != null) {
                decompileCompleted = results.decompileCompleted();
                decompileValid = results.isValid();
                isTimedOut = results.isTimedOut();
                isCancelled = results.isCancelled();
                failedToStart = results.failedToStart();
                String msg = results.getErrorMessage();
                if (msg != null && !msg.isEmpty()) {
                    decompileError = msg;
                }
            }
            if (results != null && results.decompileCompleted()) {
                DecompiledFunction df = results.getDecompiledFunction();
                if (df != null) {
                    if (df.getC() != null) {
                        pseudocode = df.getC();
                    }
                    if (df.getSignature() != null) {
                        decompilerSignature = df.getSignature();
                    }
                }
                HighFunction high = results.getHighFunction();
                if (high != null && high.getBasicBlocks() != null) {
                    basicBlockCount = high.getBasicBlocks().size();
                }
            } else if (!decompileError.isEmpty()) {
                printerr("[decompile_function] decompile failed: " + decompileError);
            }
            envelope.put("decompiler_signature", decompilerSignature);
            envelope.put("pseudocode", pseudocode);
            envelope.put("basic_block_count", basicBlockCount);
            envelope.put("decompile_completed", decompileCompleted);
            envelope.put("decompile_valid", decompileValid);
            envelope.put("is_timed_out", isTimedOut);
            envelope.put("is_cancelled", isCancelled);
            envelope.put("failed_to_start", failedToStart);
            envelope.put("decompile_error", decompileError);
        } finally {
            try {
                iface.dispose();
            } catch (Exception e) {
                printerr("[decompile_function] iface.dispose threw: " + e.getMessage());
            }
        }

        writeOutput(outputPath, envelope);
        String pseudocode = (String) envelope.get("pseudocode");
        println("[decompile_function] wrote " + (pseudocode != null ? pseudocode.length() : 0)
            + " chars of pseudocode for " + safeFullName(fn) + " to " + outputPath);
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

    private List<String> collectNames(Set<Function> fns) {
        Set<String> sorted = new TreeSet<>();
        if (fns != null) {
            for (Function f : fns) {
                if (f != null && f.getName() != null) {
                    sorted.add(f.getName());
                }
            }
        }
        return new ArrayList<>(sorted);
    }

    private List<Map<String, Object>> collectDetails(Set<Function> fns) {
        List<Map<String, Object>> refs = new ArrayList<>();
        if (fns == null) {
            return refs;
        }
        List<Function> ordered = new ArrayList<>(fns);
        ordered.sort((a, b) -> safeFullName(a).compareToIgnoreCase(safeFullName(b)));
        for (Function fn : ordered) {
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("name", safeFullName(fn));
            ref.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");
            ref.put("is_external", fn.isExternal());
            ref.put("is_thunk", fn.isThunk());
            refs.add(ref);
        }
        return refs;
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
