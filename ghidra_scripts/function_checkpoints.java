// Summarize function/range checkpoints with stack provenance and p-code counts.
// Usage: <output_path> <name_or_address> [ranges] [simplification_style]
// ranges format: "name:0x401000-0x401080;0x401080-0x401100" or empty for whole function.
// End addresses are exclusive. Always exits 0 and writes a valid envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.FlowType;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class function_checkpoints extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.function_checkpoints.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int PREVIEW_LIMIT = 40;
    private static final Pattern STACK_REF =
        Pattern.compile("\\[(e[bs]p|r[bs]p)(?:\\s*([+-])\\s*(0x[0-9a-fA-F]+|[0-9]+))?\\]", Pattern.CASE_INSENSITIVE);

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[function_checkpoints] missing args; expected <output_path> <name_or_address> [ranges] [simplification_style]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String query = args[1];
        String rangesQuery = args.length >= 3 ? args[2] : "";
        String simplificationStyle = args.length >= 4 ? args[3] : DEFAULT_SIMPLIFICATION_STYLE;

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", query);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("function_name", "");
        envelope.put("address", "");
        envelope.put("ranges_query", rangesQuery);
        envelope.put("range_count", 0);
        envelope.put("ranges", new ArrayList<>());
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");

        if (currentProgram == null) {
            envelope.put("resolution_error", "no program loaded");
            writeOutput(outputPath, envelope);
            return;
        }

        Function fn;
        try {
            fn = resolveFunction(currentProgram.getFunctionManager(), query);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            return;
        }
        envelope.put("function_name", safeFullName(fn));
        envelope.put("address", safeAddress(fn.getEntryPoint()));

        Map<Address, Instruction> instructionsByAddress = collectInstructions(fn);
        StackDeltaAnalysis stackDeltaAnalysis = computeEspDeltas(fn, fn.getBody(), instructionsByAddress);
        List<RangeSpec> ranges;
        try {
            ranges = parseRanges(rangesQuery, fn);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeOutput(outputPath, envelope);
            return;
        }

        List<PcodeEntry> pcodeEntries = collectPcode(fn, simplificationStyle, envelope);
        List<Map<String, Object>> rangeMaps = new ArrayList<>();
        for (RangeSpec range : ranges) {
            rangeMaps.add(summarizeRange(range, instructionsByAddress, stackDeltaAnalysis, pcodeEntries));
        }
        envelope.put("range_count", rangeMaps.size());
        envelope.put("ranges", rangeMaps);
        writeOutput(outputPath, envelope);
        println("[function_checkpoints] summarized " + rangeMaps.size() + " ranges for " + safeFullName(fn));
    }

    private Map<String, Object> summarizeRange(
            RangeSpec range,
            Map<Address, Instruction> instructionsByAddress,
            StackDeltaAnalysis stackDeltaAnalysis,
            List<PcodeEntry> pcodeEntries) throws Exception {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", range.name);
        out.put("start", safeAddress(range.start));
        out.put("end", safeAddress(range.end));

        int instructionCount = 0;
        int callCount = 0;
        int jumpCount = 0;
        int terminalCount = 0;
        int memoryWriteCount = 0;
        String firstInstruction = "";
        String lastInstruction = "";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Map<String, Integer> mnemonicCounts = new LinkedHashMap<>();
        List<Map<String, Object>> stackRefsPreview = new ArrayList<>();
        boolean stackRefsTruncated = false;
        int stackRefCount = 0;
        int stackWriteCount = 0;
        List<Map<String, Object>> instructionPreview = new ArrayList<>();
        boolean instructionPreviewTruncated = false;

        for (Instruction instr : instructionsByAddress.values()) {
            Address addr = instr.getAddress();
            if (!range.contains(addr)) {
                continue;
            }
            instructionCount++;
            if (firstInstruction.isEmpty()) {
                firstInstruction = instr.toString();
            }
            lastInstruction = instr.toString();
            mnemonicCounts.put(instr.getMnemonicString(), mnemonicCounts.getOrDefault(instr.getMnemonicString(), 0) + 1);
            FlowType flowType = instr.getFlowType();
            if (flowType != null && flowType.isCall()) {
                callCount++;
            }
            if (flowType != null && flowType.isJump()) {
                jumpCount++;
            }
            if (flowType != null && flowType.isTerminal()) {
                terminalCount++;
            }
            byte[] rawBytes = new byte[instr.getLength()];
            try {
                currentProgram.getMemory().getBytes(addr, rawBytes);
                digest.update(rawBytes);
            } catch (Exception e) {
                // Keep the digest deterministic for readable instructions even if bytes are unavailable.
                digest.update(instr.toString().getBytes(StandardCharsets.UTF_8));
            }
            if (instructionPreview.size() < PREVIEW_LIMIT) {
                Map<String, Object> im = new LinkedHashMap<>();
                im.put("address", safeAddress(addr));
                im.put("disassembly", instr.toString());
                instructionPreview.add(im);
            } else {
                instructionPreviewTruncated = true;
            }

            boolean writesMemory = false;
            Integer espDeltaBefore = stackDeltaAnalysis.before.get(addr);
            if (stackDeltaAnalysis.unknown.contains(addr)) {
                espDeltaBefore = null;
            }
            for (int i = 0; i < instr.getNumOperands(); i++) {
                String operand = instr.getDefaultOperandRepresentation(i);
                int operandType = instr.getOperandType(i);
                if (operand != null && operand.contains("[") && operandAccess(instr, i).contains("write")) {
                    writesMemory = true;
                }
                List<Map<String, Object>> refs = findStackRefs(instr, i, operand, espDeltaBefore);
                for (Map<String, Object> ref : refs) {
                    stackRefCount++;
                    String access = (String) ref.get("access");
                    if ("write".equals(access) || "read_write".equals(access)) {
                        stackWriteCount++;
                    }
                    ref.put("address", safeAddress(addr));
                    ref.put("disassembly", instr.toString());
                    if (stackRefsPreview.size() < PREVIEW_LIMIT) {
                        stackRefsPreview.add(ref);
                    } else {
                        stackRefsTruncated = true;
                    }
                }
            }
            if (writesMemory) {
                memoryWriteCount++;
            }
        }

        Map<String, Integer> pcodeCounts = new LinkedHashMap<>();
        List<String> pcodeSeqPreview = new ArrayList<>();
        boolean pcodePreviewTruncated = false;
        int pcodeOpCount = 0;
        for (PcodeEntry entry : pcodeEntries) {
            if (!range.contains(entry.address)) {
                continue;
            }
            pcodeOpCount++;
            pcodeCounts.put(entry.mnemonic, pcodeCounts.getOrDefault(entry.mnemonic, 0) + 1);
            if (pcodeSeqPreview.size() < PREVIEW_LIMIT) {
                pcodeSeqPreview.add(entry.address.toString() + "@" + entry.time + ":" + entry.mnemonic);
            } else {
                pcodePreviewTruncated = true;
            }
        }

        out.put("instruction_count", instructionCount);
        out.put("first_instruction", firstInstruction);
        out.put("last_instruction", lastInstruction);
        out.put("byte_sha256", toHex(digest.digest()));
        out.put("mnemonic_counts", tupleCounts(mnemonicCounts));
        out.put("call_count", callCount);
        out.put("jump_count", jumpCount);
        out.put("terminal_count", terminalCount);
        out.put("memory_write_count", memoryWriteCount);
        out.put("stack_ref_count", stackRefCount);
        out.put("stack_write_count", stackWriteCount);
        out.put("stack_refs_preview", stackRefsPreview);
        out.put("stack_refs_truncated", stackRefsTruncated);
        out.put("instruction_preview", instructionPreview);
        out.put("instruction_preview_truncated", instructionPreviewTruncated);
        out.put("pcode_op_count", pcodeOpCount);
        out.put("pcode_mnemonic_counts", tupleCounts(pcodeCounts));
        out.put("pcode_seq_preview", pcodeSeqPreview);
        out.put("pcode_preview_truncated", pcodePreviewTruncated);
        return out;
    }

    private List<PcodeEntry> collectPcode(Function fn, String simplificationStyle, Map<String, Object> envelope) {
        List<PcodeEntry> entries = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.setSimplificationStyle(simplificationStyle == null || simplificationStyle.isEmpty()
            ? DEFAULT_SIMPLIFICATION_STYLE : simplificationStyle);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);
        try {
            DecompileResults dr = decompiler.decompileFunction(fn, 60, monitor);
            if (dr == null) {
                envelope.put("decompile_error", "null result");
                return entries;
            }
            envelope.put("decompile_completed", dr.decompileCompleted());
            envelope.put("decompile_valid", dr.isValid());
            envelope.put("is_timed_out", dr.isTimedOut());
            envelope.put("is_cancelled", dr.isCancelled());
            envelope.put("failed_to_start", dr.failedToStart());
            if (!dr.decompileCompleted()) {
                envelope.put("decompile_error", dr.getErrorMessage());
                return entries;
            }
            HighFunction hf = dr.getHighFunction();
            if (hf == null) {
                envelope.put("decompile_error", "HighFunction is null");
                return entries;
            }
            Iterator<PcodeOpAST> opIt = hf.getPcodeOps();
            while (opIt.hasNext()) {
                PcodeOpAST op = opIt.next();
                if (op.getSeqnum() == null || op.getSeqnum().getTarget() == null) {
                    continue;
                }
                entries.add(new PcodeEntry(op.getSeqnum().getTarget(), op.getSeqnum().getTime(), op.getMnemonic()));
            }
        } catch (Exception e) {
            envelope.put("decompile_error", e.toString());
        } finally {
            decompiler.dispose();
        }
        return entries;
    }

    private Map<Address, Instruction> collectInstructions(Function fn) {
        Map<Address, Instruction> instructionsByAddress = new LinkedHashMap<>();
        InstructionIterator instrIt = currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (instrIt.hasNext()) {
            Instruction instr = instrIt.next();
            instructionsByAddress.put(instr.getAddress(), instr);
        }
        return instructionsByAddress;
    }

    private List<RangeSpec> parseRanges(String rangesQuery, Function fn) throws ResolutionException {
        List<RangeSpec> ranges = new ArrayList<>();
        if (rangesQuery == null || rangesQuery.trim().isEmpty()) {
            Address start = fn.getEntryPoint();
            Address end = fn.getBody().getMaxAddress().add(1);
            ranges.add(new RangeSpec("function", start, end));
            return ranges;
        }
        String[] parts = rangesQuery.split("[;,]");
        int autoIndex = 0;
        for (String raw : parts) {
            String item = raw.trim();
            if (item.isEmpty()) {
                continue;
            }
            String name = "range_" + autoIndex;
            String spec = item;
            int colon = item.indexOf(':');
            if (colon > 0) {
                name = item.substring(0, colon).trim();
                spec = item.substring(colon + 1).trim();
            }
            String[] bounds = spec.split("-");
            if (bounds.length != 2) {
                throw new ResolutionException("Invalid range '" + item + "'; expected name:start-end or start-end");
            }
            Address start = parseUserAddress(bounds[0].trim());
            Address end = parseUserAddress(bounds[1].trim());
            if (start == null || end == null) {
                throw new ResolutionException("Invalid address in range '" + item + "'");
            }
            ranges.add(new RangeSpec(name.isEmpty() ? "range_" + autoIndex : name, start, end));
            autoIndex++;
        }
        if (ranges.isEmpty()) {
            throw new ResolutionException("No valid ranges supplied.");
        }
        return ranges;
    }

    private Address parseUserAddress(String text) {
        try {
            AddressFactory af = currentProgram.getAddressFactory();
            String stripped = text;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            return af.getAddress(stripped);
        } catch (Exception e) {
            return null;
        }
    }

    private Function resolveFunction(FunctionManager fm, String nameOrAddress) throws ResolutionException {
        Address targetAddress = parseUserAddress(nameOrAddress);
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
            String qualified = safeFullName(func);
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
            for (int i = 0; i < picked.size() && i < 5; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                Function f = picked.get(i);
                sb.append(safeFullName(f)).append(" @ ").append(safeAddress(f.getEntryPoint()));
            }
            if (picked.size() > 5) {
                sb.append(" (+").append(picked.size() - 5).append(" more)");
            }
            throw new ResolutionException(sb.toString());
        }
        return picked.get(0);
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
            ref.put("access", operandAccess(instr, operandIndex));
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
                try {
                    int imm = parseInteger(src);
                    return new EspUpdate(m.equals("ADD") ? espDelta + imm : espDelta - imm, true);
                } catch (NumberFormatException nfe) {
                    return new EspUpdate(null, false);
                }
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

    private String operandAccess(Instruction instr, int operandIndex) {
        String access = operandAccess(instr.getOperandType(operandIndex));
        if (!access.isEmpty()) {
            return access;
        }
        String operand = instr.getDefaultOperandRepresentation(operandIndex);
        if (operand == null || !operand.contains("[")) {
            return "";
        }
        String mnemonic = instr.getMnemonicString();
        String m = mnemonic == null ? "" : mnemonic.toUpperCase();
        if (operandIndex == 0) {
            if (m.equals("MOV") || m.equals("LEA")) {
                return "write";
            }
            if (m.equals("ADD") || m.equals("SUB") || m.equals("XOR") || m.equals("OR")
                    || m.equals("AND") || m.equals("INC") || m.equals("DEC") || m.equals("SHL")
                    || m.equals("SHR") || m.equals("ROL") || m.equals("ROR")) {
                return "read_write";
            }
        }
        if (m.equals("PUSH") || m.equals("CMP") || m.equals("TEST") || operandIndex > 0) {
            return "read";
        }
        return "";
    }

    private List<Object[]> tupleCounts(Map<String, Integer> counts) {
        List<Object[]> out = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            out.add(new Object[] {entry.getKey(), entry.getValue()});
        }
        return out;
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

    private String safeFullName(Function func) {
        try {
            return func.getName(true);
        } catch (Exception e) {
            return func != null ? func.getName() : "";
        }
    }

    private String safeAddress(Address addr) {
        return addr != null ? addr.toString() : "";
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private void writeOutput(String outputPath, Map<String, Object> envelope) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            pw.write(gson.toJson(envelope));
        }
    }

    private static class RangeSpec {
        final String name;
        final Address start;
        final Address end;

        RangeSpec(String name, Address start, Address end) {
            this.name = name;
            this.start = start;
            this.end = end;
        }

        boolean contains(Address address) {
            return address != null && address.compareTo(start) >= 0 && address.compareTo(end) < 0;
        }
    }

    private static class PcodeEntry {
        final Address address;
        final int time;
        final String mnemonic;

        PcodeEntry(Address address, int time, String mnemonic) {
            this.address = address;
            this.time = time;
            this.mnemonic = mnemonic;
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
