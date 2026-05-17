// List typed parameters and local variables for a function.
// Usage: <output_path> <name_or_address>
// name_or_address is parsed as an address first, then falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// Prefers the decompiler-backed HighFunction symbol model so callers can see recovered
// storage metadata and lock state. Falls back to Function DB variables if decompilation
// is unavailable or fails.
// Always exits 0 and writes a valid envelope; errors populate resolution_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class variables extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.variables.v0";
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[variables] missing args; expected <output_path> <name_or_address>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];

        if (currentProgram == null) {
            printerr("[variables] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("source", "function_db");
        envelope.put("parameter_count", 0);
        envelope.put("parameters", new ArrayList<>());
        envelope.put("local_var_count", 0);
        envelope.put("local_vars", new ArrayList<>());
        envelope.put("decompiler_error", "");
        envelope.put("resolution_error", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function fn;
        try {
            fn = resolveFunction(fm, query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            println("[variables] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        List<Map<String, Object>> paramList = new ArrayList<>();
        List<Map<String, Object>> localList = new ArrayList<>();

        String source = "function_db";
        String decompilerError = "";
        DecompInterface iface = new DecompInterface();
        try {
            iface.toggleCCode(false);
            iface.openProgram(currentProgram);
            DecompileResults results = iface.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
            if (results != null && results.decompileCompleted() && results.getHighFunction() != null) {
                HighFunction high = results.getHighFunction();
                LocalSymbolMap localMap = high.getLocalSymbolMap();
                int paramCount = localMap.getNumParams();
                for (int i = 0; i < paramCount; i++) {
                    HighSymbol sym = localMap.getParamSymbol(i);
                    if (sym != null) {
                        paramList.add(highParamToMap(sym));
                    }
                }
                Iterator<HighSymbol> it = localMap.getSymbols();
                while (it.hasNext()) {
                    HighSymbol sym = it.next();
                    if (sym == null || sym.isParameter() || sym.isGlobal() || sym instanceof EquateSymbol) {
                        continue;
                    }
                    localList.add(highLocalToMap(sym, fn));
                }
                localList.sort(
                    Comparator.comparing((Map<String, Object> m) -> stringField(m, "pc_address"))
                        .thenComparing(m -> stringField(m, "storage"))
                        .thenComparing(m -> stringField(m, "name"))
                );
                source = "decompiler";
            } else if (results != null) {
                String msg = results.getErrorMessage();
                if (msg != null && !msg.isEmpty()) {
                    decompilerError = msg;
                } else {
                    decompilerError = "Decompiler did not produce a HighFunction.";
                }
            } else {
                decompilerError = "Decompiler returned no results.";
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            decompilerError = msg != null && !msg.isEmpty() ? msg : e.getClass().getSimpleName();
        } finally {
            try {
                iface.dispose();
            } catch (Exception e) {
                printerr("[variables] iface.dispose threw: " + e.getMessage());
            }
        }

        if (!"decompiler".equals(source)) {
            paramList.clear();
            localList.clear();
            Parameter[] params = fn.getParameters();
            for (Parameter p : params) {
                paramList.add(parameterToMap(p));
            }
            Variable[] localVars = fn.getLocalVariables();
            for (Variable v : localVars) {
                localList.add(localVariableToMap(v));
            }
        }

        envelope.put("source", source);
        envelope.put("parameter_count", paramList.size());
        envelope.put("parameters", paramList);
        envelope.put("local_var_count", localList.size());
        envelope.put("local_vars", localList);
        envelope.put("decompiler_error", decompilerError);

        writeOutput(outputPath, envelope);
        println("[variables] extracted " + paramList.size() + " params and "
            + localList.size() + " locals for " + safeFullName(fn) + " via " + source);
    }

    private Map<String, Object> parameterToMap(Parameter p) {
        Map<String, Object> pm = new LinkedHashMap<>();
        pm.put("name", p.getName() != null ? p.getName() : "");
        pm.put("ordinal", p.getOrdinal());
        DataType dt = p.getDataType();
        pm.put("data_type", dt != null ? dt.getDisplayName() : "unknown");
        pm.put("size", dt != null ? dt.getLength() : -1);
        VariableStorage storage = p.getVariableStorage();
        pm.put("storage", storage != null ? storage.toString() : "");
        pm.put("storage_kind", storageKind(storage));
        pm.put("pc_address", "");
        pm.put("is_name_locked", false);
        pm.put("is_type_locked", false);
        pm.put("is_this_pointer", false);
        pm.put("is_hidden_return", false);
        return pm;
    }

    private Map<String, Object> localVariableToMap(Variable v) {
        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("name", v.getName() != null ? v.getName() : "");
        DataType dt = v.getDataType();
        vm.put("data_type", dt != null ? dt.getDisplayName() : "unknown");
        vm.put("size", dt != null ? dt.getLength() : -1);
        VariableStorage storage = v.getVariableStorage();
        vm.put("storage", storage != null ? storage.toString() : "");
        vm.put("first_use_offset", v.getFirstUseOffset());
        vm.put("storage_kind", storageKind(storage));
        vm.put("pc_address", "");
        vm.put("is_name_locked", false);
        vm.put("is_type_locked", false);
        return vm;
    }

    private Map<String, Object> highParamToMap(HighSymbol sym) {
        Map<String, Object> pm = new LinkedHashMap<>();
        pm.put("name", sym.getName() != null ? sym.getName() : "");
        pm.put("ordinal", sym.getCategoryIndex());
        DataType dt = sym.getDataType();
        pm.put("data_type", dt != null ? dt.getDisplayName() : "unknown");
        pm.put("size", sym.getSize());
        VariableStorage storage = sym.getStorage();
        pm.put("storage", storage != null ? storage.toString() : "");
        pm.put("storage_kind", storageKind(storage));
        pm.put("pc_address", safeAddress(sym.getPCAddress()));
        pm.put("is_name_locked", sym.isNameLocked());
        pm.put("is_type_locked", sym.isTypeLocked());
        pm.put("is_this_pointer", sym.isThisPointer());
        pm.put("is_hidden_return", sym.isHiddenReturn());
        return pm;
    }

    private Map<String, Object> highLocalToMap(HighSymbol sym, Function fn) {
        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("name", sym.getName() != null ? sym.getName() : "");
        DataType dt = sym.getDataType();
        vm.put("data_type", dt != null ? dt.getDisplayName() : "unknown");
        vm.put("size", sym.getSize());
        VariableStorage storage = sym.getStorage();
        vm.put("storage", storage != null ? storage.toString() : "");
        vm.put("first_use_offset", firstUseOffset(sym, fn));
        vm.put("storage_kind", storageKind(storage));
        vm.put("pc_address", safeAddress(sym.getPCAddress()));
        vm.put("is_name_locked", sym.isNameLocked());
        vm.put("is_type_locked", sym.isTypeLocked());
        return vm;
    }

    private int firstUseOffset(HighSymbol sym, Function fn) {
        Address pc = sym.getPCAddress();
        if (pc == null || fn == null || fn.getEntryPoint() == null) {
            return 0;
        }
        try {
            return (int) pc.subtract(fn.getEntryPoint());
        } catch (Exception e) {
            return 0;
        }
    }

    private String storageKind(VariableStorage storage) {
        if (storage == null) {
            return "unknown";
        }
        if (storage.isAutoStorage()) {
            return "auto";
        }
        if (storage.isStackStorage()) {
            return "stack";
        }
        if (storage.isRegisterStorage()) {
            return "register";
        }
        if (storage.isMemoryStorage()) {
            return "memory";
        }
        if (storage.isConstantStorage()) {
            return "constant";
        }
        if (storage.isHashStorage()) {
            return "hash";
        }
        if (storage.isUniqueStorage()) {
            return "unique";
        }
        if (storage.isBadStorage()) {
            return "bad";
        }
        if (storage.isUnassignedStorage()) {
            return "unassigned";
        }
        return "other";
    }

    private String safeAddress(Address addr) {
        return addr != null ? addr.toString() : "";
    }

    private String stringField(Map<String, Object> m, String key) {
        Object value = m.get(key);
        return value != null ? value.toString() : "";
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
