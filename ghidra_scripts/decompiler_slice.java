// Return a bounded decompiler p-code slice rooted at a queried varnode/op.
// Usage: <output_path> <name_or_address> <query> [direction] [simplification_style] [max_ops]
// direction: forward, backward, or both. query matches varnode names, spaces, offsets, op mnemonics, or seq nums.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class decompiler_slice extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompiler_slice.v0";
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final String DEFAULT_DIRECTION = "both";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int DEFAULT_MAX_OPS = 80;
    private static final int MAX_OPS_CAP = 500;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("[decompiler_slice] missing args; expected <output_path> <name_or_address> <query> [direction] [simplification_style] [max_ops]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];
        String query = args[2];
        String direction = parseDirection(args, 3);
        String simplificationStyle = args.length >= 5 && !args[4].trim().isEmpty()
            ? args[4].trim()
            : DEFAULT_SIMPLIFICATION_STYLE;
        int maxOps = parseInt(args, 5, DEFAULT_MAX_OPS);
        if (maxOps < 1) {
            maxOps = DEFAULT_MAX_OPS;
        }
        if (maxOps > MAX_OPS_CAP) {
            maxOps = MAX_OPS_CAP;
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("direction", direction);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("seed", null);
        envelope.put("forward_op_count", 0);
        envelope.put("backward_op_count", 0);
        envelope.put("ops_returned", 0);
        envelope.put("ops_truncated", false);
        envelope.put("ops", new ArrayList<Map<String, Object>>());
        envelope.put("basic_block_count", 0);
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");
        envelope.put("slice_error", "");

        if (currentProgram == null) {
            printerr("[decompiler_slice] no program loaded");
            throw new IllegalStateException("no program");
        }

        Function fn;
        try {
            fn = resolveFunction(currentProgram.getFunctionManager(), nameOrAddress);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            return;
        }
        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        DecompInterface decompiler = new DecompInterface();
        DecompileResults dr = null;
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.setSimplificationStyle(simplificationStyle);
            decompiler.toggleSyntaxTree(true);
            decompiler.openProgram(currentProgram);
            dr = decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
        } finally {
            decompiler.dispose();
        }

        if (dr == null) {
            envelope.put("decompile_error", "null result");
            writeOutput(outputPath, envelope);
            return;
        }
        envelope.put("decompile_completed", dr.decompileCompleted());
        envelope.put("decompile_valid", dr.isValid());
        envelope.put("is_timed_out", dr.isTimedOut());
        envelope.put("is_cancelled", dr.isCancelled());
        envelope.put("failed_to_start", dr.failedToStart());
        if (dr.getErrorMessage() != null && !dr.getErrorMessage().isEmpty()) {
            envelope.put("decompile_error", dr.getErrorMessage());
        }
        if (!dr.decompileCompleted()) {
            writeOutput(outputPath, envelope);
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

        SeedMatch seed = findSeed(hf, query);
        if (seed == null || seed.varnode == null) {
            envelope.put("slice_error", "No p-code varnode or op matched query '" + query + "'.");
            writeOutput(outputPath, envelope);
            return;
        }
        envelope.put("seed", seedToMap(seed));

        List<PcodeOp> selected = new ArrayList<>();
        int forwardCount = 0;
        int backwardCount = 0;
        if ("forward".equals(direction) || "both".equals(direction)) {
            Set<PcodeOp> forward = DecompilerUtils.getForwardSliceToPCodeOps(seed.varnode);
            forwardCount = forward != null ? forward.size() : 0;
            if (forward != null) {
                selected.addAll(forward);
            }
        }
        if ("backward".equals(direction) || "both".equals(direction)) {
            Set<PcodeOp> backward = DecompilerUtils.getBackwardSliceToPCodeOps(seed.varnode);
            backwardCount = backward != null ? backward.size() : 0;
            if (backward != null) {
                selected.addAll(backward);
            }
        }
        envelope.put("forward_op_count", forwardCount);
        envelope.put("backward_op_count", backwardCount);

        selected.sort(Comparator.comparing(this::opSortKey));
        List<Map<String, Object>> ops = new ArrayList<>();
        String lastKey = "";
        boolean truncated = false;
        for (PcodeOp op : selected) {
            if (op == null) {
                continue;
            }
            String key = opSortKey(op);
            if (key.equals(lastKey)) {
                continue;
            }
            lastKey = key;
            if (ops.size() >= maxOps) {
                truncated = true;
                break;
            }
            ops.add(opToMap(op));
        }
        envelope.put("ops_returned", ops.size());
        envelope.put("ops_truncated", truncated);
        envelope.put("ops", ops);

        writeOutput(outputPath, envelope);
    }

    private SeedMatch findSeed(HighFunction hf, String query) {
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT).trim();
        Iterator<PcodeOpAST> opIt = hf.getPcodeOps();
        while (opIt.hasNext()) {
            PcodeOpAST op = opIt.next();
            if (op == null) {
                continue;
            }
            if (matchesOp(op, q)) {
                Varnode vn = op.getOutput();
                if (vn == null && op.getNumInputs() > 0) {
                    vn = op.getInput(0);
                }
                if (vn != null) {
                    return new SeedMatch(vn, op, "op");
                }
            }
            Varnode out = op.getOutput();
            if (matchesVarnode(out, q)) {
                return new SeedMatch(out, op, "output");
            }
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (matchesVarnode(in, q)) {
                    return new SeedMatch(in, op, "input_" + i);
                }
            }
        }
        return null;
    }

    private boolean matchesOp(PcodeOp op, String query) {
        if (query.isEmpty()) {
            return false;
        }
        return safeLower(op.getMnemonic()).contains(query) || opSortKey(op).toLowerCase(Locale.ROOT).contains(query);
    }

    private boolean matchesVarnode(Varnode vn, String query) {
        if (vn == null || query.isEmpty()) {
            return false;
        }
        Map<String, Object> map = varnodeToMap(vn);
        for (Object value : map.values()) {
            if (value != null && value.toString().toLowerCase(Locale.ROOT).contains(query)) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> seedToMap(SeedMatch seed) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("match_kind", seed.matchKind);
        out.put("op_seq_num", opSortKey(seed.op));
        out.put("op_mnemonic", seed.op != null ? seed.op.getMnemonic() : "");
        out.put("varnode", varnodeToMap(seed.varnode));
        return out;
    }

    private Map<String, Object> opToMap(PcodeOp op) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("seq_num", opSortKey(op));
        out.put("mnemonic", op.getMnemonic());
        Varnode output = op.getOutput();
        out.put("output", output != null ? varnodeToMap(output) : null);
        List<Map<String, Object>> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode vn = op.getInput(i);
            if (vn != null) {
                inputs.add(varnodeToMap(vn));
            }
        }
        out.put("inputs", inputs);
        return out;
    }

    private Map<String, Object> varnodeToMap(Varnode vn) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (vn == null) {
            return out;
        }
        out.put("space", vn.getAddress() != null && vn.getAddress().getAddressSpace() != null
            ? vn.getAddress().getAddressSpace().getName()
            : "");
        out.put("offset", vn.getAddress() != null ? "0x" + Long.toHexString(vn.getOffset()) : "");
        out.put("size", vn.getSize());
        out.put("is_register", vn.isRegister());
        String name = "";
        if (vn.isRegister()) {
            try {
                Register register = currentProgram.getRegister(vn.getAddress(), vn.getSize());
                if (register != null) {
                    name = register.getName();
                }
            } catch (Exception e) {
                name = "";
            }
        }
        out.put("name", name);
        return out;
    }

    private String opSortKey(PcodeOp op) {
        if (op == null || op.getSeqnum() == null) {
            return "";
        }
        return op.getSeqnum().getTarget().toString() + "@" + op.getSeqnum().getTime();
    }

    private String parseDirection(String[] args, int index) {
        if (args.length <= index || args[index] == null || args[index].trim().isEmpty()) {
            return DEFAULT_DIRECTION;
        }
        String direction = args[index].trim().toLowerCase(Locale.ROOT);
        if ("forward".equals(direction) || "backward".equals(direction) || "both".equals(direction)) {
            return direction;
        }
        return DEFAULT_DIRECTION;
    }

    private int parseInt(String[] args, int index, int defaultValue) {
        if (args.length <= index) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(args[index]);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private Function resolveFunction(FunctionManager fm, String query) throws ResolutionException {
        Address addr = parseTargetAddress(query);
        if (addr != null) {
            Function byAddr = fm.getFunctionContaining(addr);
            if (byAddr != null) {
                return byAddr;
            }
        }

        String q = query.toLowerCase(Locale.ROOT);
        List<Function> exact = new ArrayList<>();
        List<Function> partial = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            String name = safeFullName(fn);
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.equals(q)) {
                exact.add(fn);
            } else if (lower.contains(q)) {
                partial.add(fn);
            }
        }
        List<Function> picked = !exact.isEmpty() ? exact : partial;
        if (picked.isEmpty()) {
            throw new ResolutionException("Function '" + query + "' not found.");
        }
        if (picked.size() > 1) {
            throw new ResolutionException("Ambiguous match for '" + query + "'. Matches: " + summarizeFunctions(picked));
        }
        return picked.get(0);
    }

    private Address parseTargetAddress(String query) {
        try {
            AddressFactory af = currentProgram.getAddressFactory();
            String stripped = query;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            return af.getAddress(stripped);
        } catch (Exception e) {
            return null;
        }
    }

    private String summarizeFunctions(List<Function> functions) {
        StringBuilder sb = new StringBuilder();
        int shown = 0;
        for (Function f : functions) {
            if (shown > 0) {
                sb.append(", ");
            }
            sb.append(safeFullName(f));
            if (f.getEntryPoint() != null) {
                sb.append(" @ ").append(f.getEntryPoint().toString());
            }
            shown++;
            if (shown >= 5 && functions.size() > shown) {
                sb.append(" (+").append(functions.size() - shown).append(" more)");
                break;
            }
        }
        return sb.toString();
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

    private String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
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

    private static class SeedMatch {
        final Varnode varnode;
        final PcodeOp op;
        final String matchKind;

        SeedMatch(Varnode varnode, PcodeOp op, String matchKind) {
            this.varnode = varnode;
            this.op = op;
            this.matchKind = matchKind;
        }
    }

    private static class ResolutionException extends Exception {
        ResolutionException(String message) {
            super(message);
        }
    }
}
