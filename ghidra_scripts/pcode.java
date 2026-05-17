// Return high-level P-code ops for a function using the decompiler interface.
// Usage: <output_path> <name_or_address> [simplification_style]
// name_or_address is parsed as an address first, then falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// simplification_style defaults to "decompile". Supported values mirror Ghidra's
// DecompInterface.setSimplificationStyle: decompile, normalize, register, firstpass, paramid.
// Always exits 0 and writes a valid envelope; errors populate resolution_error or decompile_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class pcode extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.pcode.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[pcode] missing args; expected <output_path> <name_or_address> [simplification_style]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;

        if (currentProgram == null) {
            printerr("[pcode] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("op_count", 0);
        envelope.put("ops", new ArrayList<>());
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
            println("[pcode] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.setSimplificationStyle(simplificationStyle);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);
        DecompileResults dr = decompiler.decompileFunction(fn, 60, monitor);
        decompiler.dispose();

        if (dr == null) {
            envelope.put("decompile_error", "null result");
            writeOutput(outputPath, envelope);
            println("[pcode] decompile failed for '" + query + "'");
            return;
        }
        envelope.put("decompile_completed", dr.decompileCompleted());
        envelope.put("decompile_valid", dr.isValid());
        envelope.put("is_timed_out", dr.isTimedOut());
        envelope.put("is_cancelled", dr.isCancelled());
        envelope.put("failed_to_start", dr.failedToStart());

        if (!dr.decompileCompleted()) {
            envelope.put("decompile_error", dr.getErrorMessage());
            writeOutput(outputPath, envelope);
            println("[pcode] decompile failed for '" + query + "'");
            return;
        }

        HighFunction hf = dr.getHighFunction();
        if (hf == null) {
            envelope.put("decompile_error", "HighFunction is null");
            writeOutput(outputPath, envelope);
            return;
        }
        if (hf.getBasicBlocks() != null) {
            envelope.put("basic_block_count", hf.getBasicBlocks().size());
        }

        List<Map<String, Object>> ops = new ArrayList<>();
        Iterator<PcodeOpAST> opIt = hf.getPcodeOps();
        while (opIt.hasNext()) {
            PcodeOpAST op = opIt.next();
            Map<String, Object> opMap = new LinkedHashMap<>();
            opMap.put("seq_num", op.getSeqnum() != null
                ? op.getSeqnum().getTarget().toString() + "@" + op.getSeqnum().getTime()
                : "");
            opMap.put("mnemonic", op.getMnemonic());
            Varnode outVn = op.getOutput();
            opMap.put("output", outVn != null ? varnodeToMap(outVn) : null);
            List<Map<String, Object>> inputs = new ArrayList<>();
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode vn = op.getInput(i);
                if (vn != null) {
                    inputs.add(varnodeToMap(vn));
                }
            }
            opMap.put("inputs", inputs);
            ops.add(opMap);
        }

        envelope.put("op_count", ops.size());
        envelope.put("ops", ops);

        writeOutput(outputPath, envelope);
        println("[pcode] extracted " + ops.size() + " ops for " + safeFullName(fn));
    }

    private Map<String, Object> varnodeToMap(Varnode vn) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("space", vn.getAddress().getAddressSpace().getName());
        m.put("offset", "0x" + Long.toHexString(vn.getOffset()));
        m.put("size", vn.getSize());
        m.put("is_register", vn.isRegister());
        String name = "";
        if (vn.isRegister()) {
            try {
                ghidra.program.model.lang.Register reg =
                    currentProgram.getRegister(vn.getAddress(), vn.getSize());
                if (reg != null) {
                    name = reg.getName();
                }
            } catch (Exception e) {
                name = "";
            }
        }
        m.put("name", name);
        return m;
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
