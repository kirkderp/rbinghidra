// Resolve context-table API slots and indirect calls in one warm-path pass.
// Usage: <output_path> <target_function_or_address> <init_function> <export_resolver> <module_resolver>
//        <context_stack_offset> <limit>
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class context_api_slots extends GhidraScript {
    private static final String SCHEMA = "rbm.ghidra.context_api_slots.v0";
    private static final Pattern EBP_PATTERN = Pattern.compile("(?i)\\[\\s*EBP\\s*\\+\\s*(0x[0-9a-f]+|-?\\d+)\\s*\\]");
    private static final Pattern CTX_PATTERN = Pattern.compile("(?i)\\[\\s*([A-Z]{2,3})\\s*\\+\\s*(0x[0-9a-f]+|\\d+)\\s*\\]");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 7) {
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String targetText = clean(args[1]);
        String initText = clean(args[2]);
        String exportResolverText = clean(args[3]);
        String moduleResolverText = clean(args[4]);
        String contextOffsetText = clean(args[5]);
        int limit = parseInt(args[6], 200, 1000);

        Function target = resolveFunction(targetText);
        Address targetAnchor = target == null ? parseAddressOrNull(targetText) : target.getEntryPoint();
        Function init = resolveFunction(initText);
        Address exportResolver = resolveAddress(exportResolverText);
        Address moduleResolver = resolveAddress(moduleResolverText);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("schema", SCHEMA);
        env.put("target_function_query", targetText);
        env.put("init_function_query", initText);
        env.put("export_resolver", addrString(exportResolver));
        env.put("module_resolver", addrString(moduleResolver));
        env.put("resolution_error", "");

        if (targetAnchor == null || init == null) {
            env.put("resolution_error", "target_function/address or init_function did not resolve");
            writeEnvelope(outputPath, env);
            return;
        }

        List<Instruction> targetIns = target == null ? collectFrom(targetAnchor, limit * 20) : collect(target, limit * 20);
        List<Instruction> initIns = collect(init, limit * 20);
        Integer contextStackOffset;
        if (contextOffsetText.isEmpty()) {
            contextStackOffset = inferContextStackOffset(targetIns, init.getEntryPoint());
        } else {
            contextStackOffset = parseSigned(contextOffsetText);
        }

        env.put("target_function", target == null ? addressRow(targetAnchor) : functionRow(target));
        env.put("init_function", functionRow(init));
        env.put("context_stack_offset", contextStackOffset == null ? "" : hexSigned(contextStackOffset));
        env.put(
            "context_stack_offset_source",
            contextOffsetText.isEmpty()
                ? (contextStackOffset == null ? "auto_unresolved" : "auto")
                : "explicit"
        );

        List<Map<String, Object>> moduleSlots = collectResolverAssignments(initIns, moduleResolver, "module", limit);
        List<Map<String, Object>> apiSlots = collectResolverAssignments(initIns, exportResolver, "api", limit);
        List<Map<String, Object>> indirectCalls = collectIndirectCalls(targetIns, contextStackOffset, limit);
        env.put("module_slots", moduleSlots);
        env.put("api_slots", apiSlots);
        env.put("indirect_calls", indirectCalls);
        env.put("callsite_annotations", annotateCalls(indirectCalls, apiSlots, moduleSlots));

        writeEnvelope(outputPath, env);
    }

    private List<Map<String, Object>> collectResolverAssignments(
        List<Instruction> instructions,
        Address resolver,
        String kind,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (resolver == null) {
            return out;
        }
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins) || !targetMatches(ins, resolver)) {
                continue;
            }
            List<Map<String, Object>> pushes = precedingPushes(instructions, i, 8);
            Integer hash = firstImmediatePush(pushes);
            String moduleOperand = firstMemoryPush(pushes);
            Integer moduleOffset = contextOffsetFromOperand(moduleOperand);
            Map<String, Object> store = nextEaxStore(instructions, i + 1, 8);
            Map<String, Object> row = baseInstruction(ins);
            row.put("kind", kind);
            row.put("hash", hash == null ? "" : hex32(hash));
            row.put("module_operand", moduleOperand == null ? "" : moduleOperand);
            row.put("module_context_offset", moduleOffset == null ? "" : hex(moduleOffset));
            row.put("target_context_offset", store.getOrDefault("context_offset", ""));
            row.put("target_store", store);
            row.put("pushes", pushes);
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 8)));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> collectIndirectCalls(
        List<Instruction> instructions,
        Integer contextStackOffset,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (contextStackOffset == null) {
            return out;
        }
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins) || ins.getFlowType().isCall() && ins.getDefaultFlows().length > 0) {
                continue;
            }
            String text = ins.toString();
            Matcher m = EBP_PATTERN.matcher(text);
            if (!m.find()) {
                continue;
            }
            int stackOffset = parseSigned(m.group(1));
            Map<String, Object> row = baseInstruction(ins);
            row.put("stack_offset", hexSigned(stackOffset));
            row.put("context_offset", hex(stackOffset - contextStackOffset));
            row.put("args_preview", precedingPushes(instructions, i, 8));
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 8)));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> annotateCalls(
        List<Map<String, Object>> calls,
        List<Map<String, Object>> apiSlots,
        List<Map<String, Object>> moduleSlots
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> call : calls) {
            String ctx = (String)call.get("context_offset");
            Map<String, Object> api = findByOffset(apiSlots, ctx);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("callsite", call.get("address"));
            row.put("context_offset", ctx);
            row.put("stack_offset", call.get("stack_offset"));
            row.put("hash", api == null ? "" : api.get("hash"));
            row.put("module_context_offset", api == null ? "" : api.get("module_context_offset"));
            row.put("module_hash", "");
            if (api != null) {
                Map<String, Object> module = findByOffset(moduleSlots, (String)api.get("module_context_offset"));
                if (module != null) {
                    row.put("module_hash", module.get("hash"));
                }
            }
            row.put("args_preview", call.get("args_preview"));
            out.add(row);
        }
        return out;
    }

    private Map<String, Object> findByOffset(List<Map<String, Object>> rows, String offset) {
        for (Map<String, Object> row : rows) {
            if (offset.equals(row.get("target_context_offset"))) {
                return row;
            }
        }
        return null;
    }

    private Integer inferContextStackOffset(List<Instruction> instructions, Address initEntry) {
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins) || !targetMatches(ins, initEntry)) {
                continue;
            }
            for (int j = i - 1; j >= Math.max(0, i - 6); j--) {
                Matcher m = EBP_PATTERN.matcher(instructions.get(j).toString());
                if (m.find()) {
                    return parseSigned(m.group(1));
                }
            }
        }
        return null;
    }

    private List<Map<String, Object>> precedingPushes(List<Instruction> instructions, int callIndex, int maxBack) {
        List<Map<String, Object>> pushes = new ArrayList<>();
        for (int i = callIndex - 1; i >= 0 && callIndex - i <= maxBack; i--) {
            Instruction ins = instructions.get(i);
            if (!"PUSH".equalsIgnoreCase(ins.getMnemonicString())) {
                if (!pushes.isEmpty()) {
                    break;
                }
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("source", ins.getNumOperands() > 0 ? ins.getDefaultOperandRepresentation(0) : "");
            pushes.add(row);
        }
        return pushes;
    }

    private Integer firstImmediatePush(List<Map<String, Object>> pushes) {
        for (Map<String, Object> push : pushes) {
            String src = (String)push.get("source");
            if (src != null && src.matches("(?i)-?0x[0-9a-f]+|-?\\d+")) {
                return parseSigned(src);
            }
        }
        return null;
    }

    private String firstMemoryPush(List<Map<String, Object>> pushes) {
        for (Map<String, Object> push : pushes) {
            String src = (String)push.get("source");
            if (src != null && src.contains("[")) {
                return src;
            }
        }
        return "";
    }

    private Map<String, Object> nextEaxStore(List<Instruction> instructions, int start, int maxForward) {
        for (int i = start; i < instructions.size() && i - start < maxForward; i++) {
            Instruction ins = instructions.get(i);
            String text = ins.toString();
            if (!text.toUpperCase().contains("EAX")) {
                continue;
            }
            Integer off = contextOffsetFromOperand(text);
            if (off != null && text.toUpperCase().startsWith("MOV")) {
                Map<String, Object> row = baseInstruction(ins);
                row.put("context_offset", hex(off));
                return row;
            }
        }
        Map<String, Object> empty = new LinkedHashMap<>();
        empty.put("context_offset", "");
        return empty;
    }

    private Integer contextOffsetFromOperand(String operand) {
        if (operand == null) {
            return null;
        }
        Matcher m = CTX_PATTERN.matcher(operand);
        if (!m.find()) {
            return null;
        }
        return parseSigned(m.group(2));
    }

    private Function resolveFunction(String query) {
        Address addr = parseAddressOrNull(query);
        FunctionManager fm = currentProgram.getFunctionManager();
        if (addr != null) {
            Function f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }

        String nameLc = clean(query).toLowerCase();
        List<Function> exactMatches = new ArrayList<>();
        List<Function> partialMatches = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String qualified = f.getName(true);
            String simple = f.getName();
            if (qualified.equalsIgnoreCase(query) || simple.equalsIgnoreCase(query)) {
                exactMatches.add(f);
            } else if (qualified.toLowerCase().contains(nameLc) || simple.toLowerCase().contains(nameLc)) {
                partialMatches.add(f);
            }
        }
        if (exactMatches.size() == 1) {
            return exactMatches.get(0);
        }
        if (exactMatches.isEmpty() && partialMatches.size() == 1) {
            return partialMatches.get(0);
        }
        return null;
    }

    private Address resolveAddress(String query) {
        Address addr = parseAddressOrNull(query);
        if (addr != null) {
            return addr;
        }
        Function f = resolveFunction(query);
        return f == null ? null : f.getEntryPoint();
    }

    private List<Instruction> collect(Function f, int max) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && out.size() < max) {
            out.add(it.next());
        }
        return out;
    }

    private List<Instruction> collectFrom(Address address, int max) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(address, true);
        while (it.hasNext() && out.size() < max) {
            out.add(it.next());
        }
        return out;
    }

    private boolean isCall(Instruction ins) {
        return ins.getFlowType().isCall();
    }

    private boolean targetMatches(Instruction ins, Address target) {
        Address[] flows = ins.getDefaultFlows();
        for (Address flow : flows) {
            if (flow.equals(target)) {
                return true;
            }
        }
        return ins.toString().toLowerCase().contains(target.toString().toLowerCase());
    }

    private Map<String, Object> baseInstruction(Instruction ins) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("address", ins.getAddress().toString());
        row.put("mnemonic", ins.getMnemonicString());
        row.put("disassembly", ins.toString());
        return row;
    }

    private Map<String, Object> functionRow(Function f) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", f.getName(true));
        row.put("address", f.getEntryPoint().toString());
        return row;
    }

    private Map<String, Object> addressRow(Address address) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", "");
        row.put("address", address.toString());
        return row;
    }

    private List<String> context(List<Instruction> instructions, int start, int end) {
        List<String> rows = new ArrayList<>();
        for (int i = start; i < end && i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            rows.add(ins.getAddress().toString() + " " + ins.toString());
        }
        return rows;
    }

    private Address parseAddressOrNull(String text) {
        String s = clean(text);
        if (s.isEmpty()) {
            return null;
        }
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                s = s.substring(2);
            }
            AddressFactory af = currentProgram.getAddressFactory();
            return af.getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    private int parseInt(String text, int defaultValue, int cap) {
        try {
            int value = Integer.parseInt(clean(text));
            if (value <= 0) {
                return defaultValue;
            }
            return Math.min(value, cap);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private int parseSigned(String text) {
        String s = clean(text).toLowerCase();
        long value;
        if (s.startsWith("-0x")) {
            value = -Long.parseLong(s.substring(3), 16);
        } else if (s.startsWith("0x")) {
            value = Long.parseLong(s.substring(2), 16);
            if (value > 0x7fff_ffffL) {
                value -= 0x1_0000_0000L;
            }
        } else {
            value = Long.parseLong(s);
        }
        return (int)value;
    }

    private String addrString(Address a) {
        return a == null ? "" : a.toString();
    }

    private String hex(int value) {
        return String.format("0x%x", value);
    }

    private String hexSigned(int value) {
        return value < 0 ? String.format("-0x%x", -value) : String.format("0x%x", value);
    }

    private String hex32(int value) {
        return String.format("0x%08x", value);
    }

    private String clean(String s) {
        return s == null ? "" : s.trim();
    }

    private void writeEnvelope(String outputPath, Map<String, Object> env) throws Exception {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Path out = Paths.get(outputPath);
        Files.createDirectories(out.getParent());
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(out))) {
            writer.println(gson.toJson(env));
        }
    }
}
