// Return raw instruction listing for a function.
// Usage: <output_path> <name_or_address> [max_instructions] [include_analysis]
// name_or_address is parsed as an address first, then falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// Always exits 0 and writes a valid envelope; errors populate resolution_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class disassemble extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.disassemble.v0";
    private static final int DEFAULT_MAX_INSTRUCTIONS = 32;
    private static final int HARD_MAX_INSTRUCTIONS = 512;
    private static final Pattern STACK_REF =
        Pattern.compile("\\[(e[bs]p|r[bs]p)(?:\\s*([+-])\\s*(0x[0-9a-fA-F]+|[0-9]+))?\\]", Pattern.CASE_INSENSITIVE);

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[disassemble] missing args; expected <output_path> <name_or_address>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
        int maxInstructions = parseMaxInstructions(args.length >= 3 ? args[2] : "");
        boolean includeAnalysis = parseIncludeAnalysis(args.length >= 4 ? args[3] : "");

        if (currentProgram == null) {
            printerr("[disassemble] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("instruction_count", 0);
        envelope.put("instructions_returned", 0);
        envelope.put("truncated", false);
        envelope.put("instructions", new ArrayList<>());
        envelope.put("resolution_error", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function fn;
        try {
            fn = resolveFunction(fm, query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            println("[disassemble] resolution failed for '" + query + "': " + re.getMessage());
            return;
        }

        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", fn.getEntryPoint() != null ? fn.getEntryPoint().toString() : "");

        AddressSetView body = fn.getBody();
        InstructionIterator instrIt = currentProgram.getListing().getInstructions(body, true);
        Map<Address, Instruction> instructionsByAddress = new LinkedHashMap<>();
        while (instrIt.hasNext()) {
            Instruction instr = instrIt.next();
            instructionsByAddress.put(instr.getAddress(), instr);
        }
        StackDeltaAnalysis stackDeltaAnalysis = includeAnalysis
            ? computeEspDeltas(fn, body, instructionsByAddress)
            : new StackDeltaAnalysis();
        List<Map<String, Object>> instrList = new ArrayList<>();
        int totalInstructions = instructionsByAddress.size();
        for (Instruction instr : instructionsByAddress.values()) {
            if (instrList.size() >= maxInstructions) {
                break;
            }
            Map<String, Object> im = new LinkedHashMap<>();
            Address instrAddr = instr.getAddress();
            Integer espDeltaBefore = stackDeltaAnalysis.before.get(instrAddr);
            if (stackDeltaAnalysis.unknown.contains(instrAddr)) {
                espDeltaBefore = null;
            }
            im.put("address", instr.getAddress().toString());
            byte[] rawBytes = new byte[instr.getLength()];
            try {
                currentProgram.getMemory().getBytes(instr.getAddress(), rawBytes);
            } catch (Exception e) {
                rawBytes = new byte[0];
            }
            StringBuilder hexBytes = new StringBuilder();
            for (byte b : rawBytes) {
                hexBytes.append(String.format("%02x", b & 0xff));
            }
            im.put("bytes", hexBytes.toString());
            im.put("mnemonic", instr.getMnemonicString());
            List<String> operands = new ArrayList<>();
            List<Map<String, Object>> stackRefs = new ArrayList<>();
            for (int i = 0; i < instr.getNumOperands(); i++) {
                String operand = instr.getDefaultOperandRepresentation(i);
                operands.add(operand);
                stackRefs.addAll(findStackRefs(instr, i, operand, espDeltaBefore));
            }
            im.put("operands", operands);
            im.put("disassembly", instr.toString());
            if (includeAnalysis) {
                im.put("esp_delta_before", espDeltaBefore);
                im.put("stack_refs", stackRefs);
                FlowType flowType = instr.getFlowType();
                im.put("flow_type", flowType != null ? flowType.toString() : "");
                im.put("fall_through", safeAddress(instr.getFallThrough()));
                im.put("flows", addressesToStrings(instr.getFlows()));
                im.put("default_flows", addressesToStrings(instr.getDefaultFlows()));
                im.put("has_fallthrough", instr.hasFallthrough());
                im.put("is_call", flowType != null && flowType.isCall());
                im.put("is_jump", flowType != null && flowType.isJump());
                im.put("is_terminal", flowType != null && flowType.isTerminal());
                Integer espDeltaAfter = null;
                if (espDeltaBefore != null) {
                    EspUpdate update = updateEspDelta(instr, espDeltaBefore, true);
                    if (update.known) {
                        espDeltaAfter = update.delta;
                    }
                }
                im.put("esp_delta_after", espDeltaAfter);
                im.put("esp_delta_known", espDeltaBefore != null && espDeltaAfter != null);
            }
            instrList.add(im);
        }

        envelope.put("instruction_count", totalInstructions);
        envelope.put("instructions_returned", instrList.size());
        envelope.put("truncated", totalInstructions > instrList.size());
        envelope.put("instructions", instrList);

        writeOutput(outputPath, envelope);
        println("[disassemble] extracted " + instrList.size() + " of " + totalInstructions + " instructions for " + safeFullName(fn));
    }

    private int parseMaxInstructions(String raw) {
        int value = DEFAULT_MAX_INSTRUCTIONS;
        if (raw != null && !raw.trim().isEmpty()) {
            try {
                value = Integer.parseInt(raw.trim());
            } catch (Exception e) {
                value = DEFAULT_MAX_INSTRUCTIONS;
            }
        }
        if (value <= 0) {
            value = DEFAULT_MAX_INSTRUCTIONS;
        }
        return Math.min(value, HARD_MAX_INSTRUCTIONS);
    }

    private boolean parseIncludeAnalysis(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim().toLowerCase();
        return value.equals("true") || value.equals("1") || value.equals("yes") || value.equals("analysis");
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

    private List<Map<String, Object>> findStackRefs(
            Instruction instr, int operandIndex, String operand, Integer espDeltaBefore) {
        List<Map<String, Object>> refs = new ArrayList<>();
        if (operand == null) {
            return refs;
        }
        Matcher matcher = STACK_REF.matcher(operand);
        while (matcher.find()) {
            String base = matcher.group(1).toUpperCase();
            String sign = matcher.group(2);
            String value = matcher.group(3);
            int displacement = 0;
            if (value != null && !value.isEmpty()) {
                displacement = parseInteger(value);
                if ("-".equals(sign)) {
                    displacement = -displacement;
                }
            }

            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("operand_index", operandIndex);
            ref.put("operand", operand);
            ref.put("base_register", base);
            ref.put("displacement", displacement);
            ref.put("displacement_hex", signedHex(displacement));
            if (espDeltaBefore != null && ("ESP".equals(base) || "RSP".equals(base))) {
                int canonical = espDeltaBefore + displacement;
                ref.put("canonical_stack_offset", canonical);
                ref.put("canonical_stack_offset_hex", signedHex(canonical));
            } else {
                ref.put("canonical_stack_offset", null);
                ref.put("canonical_stack_offset_hex", "");
            }
            int operandType = instr.getOperandType(operandIndex);
            ref.put("access", operandAccess(operandType));
            refs.add(ref);
        }
        return refs;
    }

    private EspUpdate updateEspDelta(Instruction instr, Integer espDelta, boolean espDeltaKnown) {
        if (!espDeltaKnown || espDelta == null) {
            return new EspUpdate(null, false);
        }
        String mnemonic = instr.getMnemonicString();
        if (mnemonic == null) {
            return new EspUpdate(espDelta, true);
        }
        String m = mnemonic.toUpperCase();
        if (m.equals("PUSH")) {
            return new EspUpdate(espDelta - currentProgram.getDefaultPointerSize(), true);
        }
        if (m.equals("POP")) {
            return new EspUpdate(espDelta + currentProgram.getDefaultPointerSize(), true);
        }
        if ((m.equals("ADD") || m.equals("SUB")) && instr.getNumOperands() >= 2) {
            String dst = instr.getDefaultOperandRepresentation(0);
            String src = instr.getDefaultOperandRepresentation(1);
            if (dst != null && src != null && dst.equalsIgnoreCase("ESP")) {
                int imm;
                try {
                    imm = parseInteger(src);
                } catch (NumberFormatException nfe) {
                    return new EspUpdate(null, false);
                }
                return new EspUpdate(m.equals("ADD") ? espDelta + imm : espDelta - imm, true);
            }
        }
        if (m.equals("LEAVE") || m.equals("ENTER")) {
            return new EspUpdate(null, false);
        }
        return new EspUpdate(espDelta, true);
    }

    private StackDeltaAnalysis computeEspDeltas(
            Function fn, AddressSetView body, Map<Address, Instruction> instructionsByAddress) {
        StackDeltaAnalysis analysis = new StackDeltaAnalysis();
        Address entry = fn.getEntryPoint();
        if (entry == null || !instructionsByAddress.containsKey(entry)) {
            return analysis;
        }

        ArrayDeque<Address> work = new ArrayDeque<>();
        setDelta(analysis, entry, 0, work);

        while (!work.isEmpty()) {
            Address address = work.removeFirst();
            if (analysis.unknown.contains(address)) {
                continue;
            }
            Integer before = analysis.before.get(address);
            Instruction instr = instructionsByAddress.get(address);
            if (before == null || instr == null) {
                continue;
            }
            EspUpdate update = updateEspDelta(instr, before, true);
            if (!update.known || update.delta == null) {
                continue;
            }

            FlowType flowType = instr.getFlowType();
            if (instr.hasFallthrough()) {
                Address fallThrough = instr.getFallThrough();
                if (fallThrough != null && body.contains(fallThrough)) {
                    setDelta(analysis, fallThrough, update.delta, work);
                }
            }
            if (flowType != null && !flowType.isCall()) {
                for (Address target : instr.getFlows()) {
                    if (target != null && body.contains(target)) {
                        setDelta(analysis, target, update.delta, work);
                    }
                }
            }
        }
        return analysis;
    }

    private void setDelta(StackDeltaAnalysis analysis, Address address, int delta, ArrayDeque<Address> work) {
        if (analysis.unknown.contains(address)) {
            return;
        }
        Integer existing = analysis.before.get(address);
        if (existing == null) {
            analysis.before.put(address, delta);
            work.add(address);
            return;
        }
        if (existing != delta) {
            analysis.before.remove(address);
            analysis.unknown.add(address);
            work.add(address);
        }
    }

    private String operandAccess(int operandType) {
        boolean reads = OperandType.doesRead(operandType);
        boolean writes = OperandType.doesWrite(operandType);
        if (reads && writes) {
            return "read_write";
        }
        if (writes) {
            return "write";
        }
        if (reads) {
            return "read";
        }
        return "";
    }

    private int parseInteger(String value) {
        String v = value.trim();
        if (v.startsWith("0x") || v.startsWith("0X")) {
            return (int) Long.parseLong(v.substring(2), 16);
        }
        return Integer.parseInt(v);
    }

    private String signedHex(int value) {
        if (value < 0) {
            return "-0x" + Integer.toHexString(-value);
        }
        return "0x" + Integer.toHexString(value);
    }

    private List<String> addressesToStrings(Address[] addrs) {
        List<String> values = new ArrayList<>();
        if (addrs == null) {
            return values;
        }
        for (Address addr : addrs) {
            values.add(safeAddress(addr));
        }
        return values;
    }

    private String safeAddress(Address addr) {
        return addr != null ? addr.toString() : "";
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

    private static class EspUpdate {
        final Integer delta;
        final boolean known;

        EspUpdate(Integer delta, boolean known) {
            this.delta = delta;
            this.known = known;
        }
    }

    private static class StackDeltaAnalysis {
        final Map<Address, Integer> before = new HashMap<>();
        final Set<Address> unknown = new HashSet<>();
    }
}
