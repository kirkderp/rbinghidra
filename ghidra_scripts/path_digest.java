// Macro path digest for one function or address range.
// Usage: <output_path> <name_or_address> <range_start> <range_end> <stop_addresses_csv> <state_register> <max_instructions> <max_events>
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class path_digest extends GhidraScript {
    private static final String SCHEMA = "rbm.ghidra.path_digest.v0";
    private static final Pattern IMM = Pattern.compile("(?i)\\b0x([0-9a-f]{1,16})\\b|\\b(\\d{1,20})\\b");
    private static final Pattern MEM_OPERAND_PATTERN = Pattern.compile("(?i)^(.+?)([+-])(0x[0-9a-f]+|\\d+)$");
    private static final Pattern STACK_ARG_PATTERN = Pattern.compile("\\+0x([0-9a-f]+)|\\+(\\d+)");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 8) {
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String nameOrAddress = args[1];
        String rangeStart = trim(args[2]);
        String rangeEnd = trim(args[3]);
        Set<String> stopAddresses = parseStopAddresses(args[4]);
        String stateRegister = normalizeRegister(emptyDefault(args[5], "esi"));
        int maxInstructions = clamp(parseInt(args[6], 800), 1, 5000);
        int maxEvents = clamp(parseInt(args[7], 200), 1, 1000);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("schema", SCHEMA);
        env.put("function_query", nameOrAddress);
        env.put("range_start", rangeStart);
        env.put("range_end", rangeEnd);
        env.put("stop_addresses", new ArrayList<String>(stopAddresses));
        env.put("state_register", stateRegister);
        env.put("max_instructions", maxInstructions);
        env.put("max_events", maxEvents);
        env.put("resolved_address", "");
        env.put("resolved_function_name", "");
        env.put("scope_kind", "");
        env.put("scope_warning", "");
        env.put("instruction_count", 0);
        env.put("truncated", false);
        env.put("stopped_at", "");
        env.put("block_count", 0);
        env.put("event_count", 0);
        env.put("local_buffer_count", 0);
        env.put("decoded_local_buffer_count", 0);
        env.put("constant_count", 0);
        env.put("blocks", new ArrayList<Map<String, Object>>());
        env.put("events", new ArrayList<Map<String, Object>>());
        env.put("local_buffers", new ArrayList<Map<String, Object>>());
        env.put("decoded_local_buffers", new ArrayList<Map<String, Object>>());
        env.put("constants_preview", new ArrayList<String>());
        env.put("resolution_error", "");

        Address start = parseAddressOrNull(rangeStart);
        Address end = parseAddressOrNull(rangeEnd);
        List<Instruction> instructions;
        try {
            Function function = resolveFunction(currentProgram.getFunctionManager(), nameOrAddress);
            env.put("resolved_address", function.getEntryPoint().toString());
            env.put("resolved_function_name", safeFullName(function));
            env.put("scope_kind", "function");
            instructions = instructionsIn(function.getBody(), start, end, maxInstructions);
        } catch (ResolutionException err) {
            Address anchor = start == null ? parseAddressOrNull(nameOrAddress) : start;
            if (anchor == null) {
                env.put("resolution_error", err.getMessage());
                writeEnvelope(outputPath, env);
                return;
            }
            Address scanEnd = end == null ? addDefaultRange(anchor) : end;
            env.put("resolved_address", anchor.toString());
            env.put("scope_kind", "address_range");
            env.put("scope_warning", "no containing Ghidra function; scanned address range");
            env.put("range_start", anchor.toString());
            env.put("range_end", scanEnd.toString());
            instructions = instructionsInRange(anchor, scanEnd, maxInstructions);
        }

        List<Instruction> clipped = clipAtStop(instructions, stopAddresses, env);
        env.put("instruction_count", clipped.size());
        env.put("truncated", instructions.size() >= maxInstructions);

        List<Map<String, Object>> events = collectEvents(clipped, stateRegister, maxEvents);
        List<Map<String, Object>> blocks = summarizeBlocks(clipped, events);
        List<Map<String, Object>> buffers = collectLocalBuffers(clipped, Math.min(maxEvents, 500));
        List<Map<String, Object>> decodedBuffers = collectDecodedLocalBuffers(clipped, Math.min(maxEvents, 500));
        List<String> constants = collectConstants(clipped, 80);

        env.put("blocks", blocks);
        env.put("block_count", blocks.size());
        env.put("events", events);
        env.put("event_count", events.size());
        env.put("local_buffers", buffers);
        env.put("local_buffer_count", buffers.size());
        env.put("decoded_local_buffers", decodedBuffers);
        env.put("decoded_local_buffer_count", decodedBuffers.size());
        env.put("constants_preview", constants);
        env.put("constant_count", constants.size());

        writeEnvelope(outputPath, env);
    }

    private List<Map<String, Object>> collectEvents(List<Instruction> instructions, String stateRegister, int maxEvents) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < instructions.size() && out.size() < maxEvents; i++) {
            Instruction ins = instructions.get(i);
            FlowType flow = ins.getFlowType();
            String mnemonic = ins.getMnemonicString();
            String op0 = operand(ins, 0);
            String op1 = operand(ins, 1);
            String text = ins.toString();

            if (flow != null && flow.isCall()) {
                Map<String, Object> row = baseEvent("call", ins);
                row.put("target_name", targetName(ins));
                row.put("target_address", targetAddress(ins));
                row.put("args_preview", recoverStackArgs(instructions, i));
                row.put("return_consumers_preview", returnConsumers(instructions, i));
                out.add(row);
                continue;
            }
            if (flow != null && flow.isJump()) {
                Map<String, Object> row = baseEvent(isIndirectJump(ins) ? "indirect_jump" : "jump", ins);
                row.put("operand0", op0);
                row.put("flows", flows(ins));
                row.put("condition_preview", nearbyPredicate(instructions, i));
                out.add(row);
                continue;
            }
            if (flow != null && flow.isTerminal()) {
                out.add(baseEvent("terminal", ins));
                continue;
            }
            if (isStateWrite(op0, stateRegister)) {
                Map<String, Object> row = baseEvent("state_write", ins);
                row.put("field", op0);
                row.put("value", op1);
                row.put("nearby_calls", nearbyCalls(instructions, i, 16));
                out.add(row);
                continue;
            }
            MemoryWrite write = immediateMemoryWrite(ins);
            if (write != null) {
                Map<String, Object> row = baseEvent("immediate_write", ins);
                row.put("base", write.base);
                row.put("offset", "0x" + Integer.toHexString(write.offset));
                row.put("size", write.size);
                row.put("value", "0x" + Long.toUnsignedString(write.value, 16));
                out.add(row);
                continue;
            }
            if (isInterestingImmediate(text)) {
                Map<String, Object> row = baseEvent("constant", ins);
                row.put("constants", immediates(text));
                out.add(row);
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectDecodedLocalBuffers(List<Instruction> instructions, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        List<BufferSeed> seeds = collectBufferSeeds(instructions, Math.min(limit * 4, 512));
        Set<String> seen = new HashSet<>();
        for (BufferSeed seed : seeds) {
            if (out.size() >= limit) {
                break;
            }
            DecodeResult result = emulateSeedWindow(instructions, seed, 260, 60000);
            if (result.mutatedByteCount == 0 || result.differentByteCount == 0) {
                continue;
            }
            List<Integer> decoded = trimDecodedBytes(result.decodedBytes);
            if (!hasInterestingDecodedBytes(decoded)) {
                continue;
            }
            String key = seed.base + ":" + seed.minOffset + ":" + seed.maxOffset + ":" + bytesToHex(decoded);
            if (!seen.add(key)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("base", seed.base);
            row.put("seed_first_address", instructions.get(seed.firstIndex).getAddress().toString());
            row.put("seed_last_address", instructions.get(seed.lastIndex).getAddress().toString());
            row.put("min_offset", "0x" + Integer.toHexString(result.minOffset));
            row.put("max_offset", "0x" + Integer.toHexString(result.maxOffset));
            row.put("byte_count", decoded.size());
            row.put("mutated_byte_count", result.mutatedByteCount);
            row.put("different_byte_count", result.differentByteCount);
            row.put("encoded_hex", bytesToHex(trimTrailingZeros(result.encodedBytes)));
            row.put("decoded_hex", bytesToHex(decoded));
            row.put("decoded_ascii", bytesToAscii(decoded));
            row.put("decoded_utf16le", bytesToUtf16Le(decoded));
            row.put("first_mutation", instructionPreview(instructions, result.firstMutationIndex));
            row.put("last_mutation", instructionPreview(instructions, result.lastMutationIndex));
            row.put("stopped_at", instructionPreview(instructions, result.stopIndex));
            row.put("branch_count", result.branchCount);
            row.put("seed_writes_preview", seed.writes);
            row.put("nearby_consumers", nearbyCalls(instructions, Math.max(result.stopIndex, seed.lastIndex), 48));
            out.add(row);
        }
        return out;
    }

    private List<BufferSeed> collectBufferSeeds(List<Instruction> instructions, int limit) {
        List<BufferSeed> out = new ArrayList<>();
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            MemoryWrite first = immediateMemoryWrite(instructions.get(i));
            if (first == null) {
                continue;
            }

            BufferSeed seed = new BufferSeed(first.base, i);
            int j = i;
            int matchingWrites = 0;
            while (j < instructions.size() && j <= i + 120 && seed.bytesByOffset.size() < 512) {
                Instruction cur = instructions.get(j);
                MemoryWrite write = immediateMemoryWrite(cur);
                if (write == null || !write.base.equals(first.base)) {
                    if (matchingWrites >= 2 && distanceToNextSameBaseWrite(instructions, j, first.base, 12) < 0) {
                        break;
                    }
                    j++;
                    continue;
                }
                seed.addWrite(write, cur, j);
                matchingWrites++;
                j++;
            }
            if (matchingWrites < 2 || seed.bytesByOffset.size() < 3 || !hasNonZeroByte(seed.bytesByOffset)) {
                continue;
            }
            out.add(seed);
            i = Math.max(i, seed.lastIndex);
        }
        return out;
    }

    private int distanceToNextSameBaseWrite(List<Instruction> instructions, int start, String base, int limit) {
        for (int i = start; i < instructions.size() && i <= start + limit; i++) {
            MemoryWrite write = immediateMemoryWrite(instructions.get(i));
            if (write != null && write.base.equals(base)) {
                return i - start;
            }
        }
        return -1;
    }

    private DecodeResult emulateSeedWindow(List<Instruction> instructions, BufferSeed seed, int windowInstructions, int maxSteps) {
        MicroState state = new MicroState();
        for (Map.Entry<Integer, Integer> entry : seed.bytesByOffset.entrySet()) {
            writeSeedMemory(state, seed.base, entry.getKey(), entry.getValue());
        }

        int startPc = Math.max(0, seed.firstIndex - 20);
        int endPc = Math.min(instructions.size(), seed.firstIndex + windowInstructions);
        int pc = startPc;
        int steps = 0;
        Map<Integer, Integer> loopCounts = new LinkedHashMap<>();
        DecodeResult result = new DecodeResult();
        while (pc >= startPc && pc < endPc && steps++ < maxSteps) {
            Instruction ins = instructions.get(pc);
            if (isCall(ins) && result.firstMutationIndex >= 0 && pc > result.lastMutationIndex) {
                result.stopIndex = pc;
                break;
            }

            String mnemonic = ins.getMnemonicString().toUpperCase();
            String op0 = operand(ins, 0);
            String op1 = operand(ins, 1);
            int nextPc = pc + 1;

            if ("MOV".equals(mnemonic)) {
                executeMov(state, ins, pc, op0, op1);
            } else if ("MOVZX".equals(mnemonic)) {
                executeMov(state, ins, pc, op0, op1);
            } else if ("LEA".equals(mnemonic)) {
                Long value = evalLea(state, op1);
                if (value != null) {
                    writeRegister(state, op0, value);
                }
            } else if ("XOR".equals(mnemonic) || "OR".equals(mnemonic) || "AND".equals(mnemonic)
                || "ADD".equals(mnemonic) || "SUB".equals(mnemonic)) {
                Long left = readOperand(state, op0);
                Long right = readOperand(state, op1);
                if (left != null && right != null) {
                    long opResult = binaryOp(mnemonic, left, right);
                    writeOperand(state, ins, pc, op0, opResult, true);
                }
            } else if ("NOT".equals(mnemonic)) {
                Long value = readOperand(state, op0);
                if (value != null) {
                    writeOperand(state, ins, pc, op0, ~value, true);
                }
            } else if ("INC".equals(mnemonic) || "DEC".equals(mnemonic)) {
                Long value = readOperand(state, op0);
                if (value != null) {
                    writeOperand(state, ins, pc, op0, "INC".equals(mnemonic) ? value + 1 : value - 1, true);
                }
            } else if ("CMP".equals(mnemonic) || "TEST".equals(mnemonic)) {
                Long left = readOperand(state, op0);
                Long right = "TEST".equals(mnemonic) ? readOperand(state, op0) : readOperand(state, op1);
                if (left != null && right != null) {
                    long cmpResult = "TEST".equals(mnemonic) ? (left & right) : (left - right);
                    state.zf = (cmpResult & 0xffffffffL) == 0;
                    state.sf = (cmpResult & 0x80000000L) != 0;
                    state.cf = Long.compareUnsigned(left & 0xffffffffL, right & 0xffffffffL) < 0;
                }
            } else if (mnemonic.startsWith("J")) {
                Address target = firstFlow(ins);
                int targetIndex = target == null ? -1 : instructionIndex(instructions, target);
                if (targetIndex >= 0 && targetIndex < pc && branchTaken(state, mnemonic)) {
                    int count = loopCounts.getOrDefault(pc, 0);
                    if (count < 1024) {
                        loopCounts.put(pc, count + 1);
                        result.branchCount++;
                        nextPc = targetIndex;
                    }
                }
            }
            updateDecodeMutation(result, state, seed, pc);
            result.stopIndex = pc;
            pc = nextPc;
        }
        result.finish(state, seed);
        return result;
    }

    private void executeMov(MicroState state, Instruction ins, int instructionIndex, String dst, String src) {
        Long value = readOperand(state, src);
        if (value == null) {
            return;
        }
        writeOperand(state, ins, instructionIndex, dst, value, !isImmediateOnly(src));
    }

    private void writeOperand(MicroState state, Instruction ins, int instructionIndex, String dst, long value, boolean dynamic) {
        MemoryOperandEx mem = memoryOperandEx(dst, state);
        if (mem != null && !mem.base.isEmpty()) {
            int size = operandWriteSize(dst);
            if (size <= 0) {
                size = 4;
            }
            writeMemory(state, mem.base, mem.offset, size, value, ins, instructionIndex, dynamic);
            return;
        }
        writeRegister(state, dst, value);
    }

    private long binaryOp(String op, long left, long right) {
        long result;
        if ("XOR".equals(op)) {
            result = left ^ right;
        } else if ("OR".equals(op)) {
            result = left | right;
        } else if ("AND".equals(op)) {
            result = left & right;
        } else if ("ADD".equals(op)) {
            result = left + right;
        } else {
            result = left - right;
        }
        return result & 0xffffffffL;
    }

    private boolean branchTaken(MicroState state, String mnemonic) {
        if ("JNZ".equals(mnemonic) || "JNE".equals(mnemonic)) {
            return !state.zf;
        }
        if ("JZ".equals(mnemonic) || "JE".equals(mnemonic)) {
            return state.zf;
        }
        if ("JC".equals(mnemonic) || "JB".equals(mnemonic) || "JNAE".equals(mnemonic)) {
            return state.cf;
        }
        if ("JNC".equals(mnemonic) || "JNB".equals(mnemonic) || "JAE".equals(mnemonic)) {
            return !state.cf;
        }
        if ("JS".equals(mnemonic)) {
            return state.sf;
        }
        if ("JNS".equals(mnemonic)) {
            return !state.sf;
        }
        return false;
    }

    private Long readOperand(MicroState state, String operand) {
        String op = operand == null ? "" : operand.trim();
        if (op.isEmpty()) {
            return null;
        }
        Long imm = parseImmediate(op);
        if (imm != null && isImmediateOnly(op)) {
            return imm & 0xffffffffL;
        }
        MemoryOperandEx mem = memoryOperandEx(op, state);
        if (mem != null) {
            int size = operandWriteSize(op);
            if (size <= 0) {
                size = 4;
            }
            return readMemory(state, mem.base, mem.offset, size);
        }
        return readRegister(state, op);
    }

    private Long evalLea(MicroState state, String operand) {
        String op = operand == null ? "" : operand;
        int open = op.indexOf('[');
        int close = op.indexOf(']');
        if (open < 0 || close <= open) {
            return null;
        }
        String inner = op.substring(open + 1, close).replace(" ", "");
        if (inner.contains(":")) {
            return null;
        }
        String[] parts = inner.replace("-", "+-").split("\\+");
        long value = 0;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            long sign = 1;
            String p = part;
            if (p.startsWith("-")) {
                sign = -1;
                p = p.substring(1);
            }
            if (p.contains("*")) {
                String[] pair = p.split("\\*", 2);
                Long reg = readRegister(state, pair[0]);
                Long scale = parseLongLiteral(pair[1]);
                if (reg == null || scale == null) {
                    return null;
                }
                value = (value + sign * ((reg & 0xffffffffL) * scale)) & 0xffffffffL;
            } else if (regName(p).length() > 0) {
                Long reg = readRegister(state, p);
                if (reg == null) {
                    return null;
                }
                value = (value + sign * (reg & 0xffffffffL)) & 0xffffffffL;
            } else {
                Long imm = parseLongLiteral(p);
                if (imm == null) {
                    return null;
                }
                value = (value + sign * imm) & 0xffffffffL;
            }
        }
        return value & 0xffffffffL;
    }

    private boolean isImmediateOnly(String operand) {
        String op = operand == null ? "" : operand.trim().toLowerCase();
        return op.matches("-?0x[0-9a-f]+") || op.matches("-?\\d+");
    }

    private Long readRegister(MicroState state, String reg) {
        String r = regName(reg);
        if (r.isEmpty()) {
            return null;
        }
        long value = state.registers.getOrDefault(registerBase(r), 0L);
        if (r.length() == 2 && r.endsWith("L")) {
            return value & 0xffL;
        }
        if (r.length() == 2 && r.endsWith("X")) {
            return value & 0xffffL;
        }
        return value & 0xffffffffL;
    }

    private void writeRegister(MicroState state, String reg, long value) {
        String r = regName(reg);
        if (r.isEmpty()) {
            return;
        }
        String base = registerBase(r);
        long old = state.registers.getOrDefault(base, 0L);
        long v = value & 0xffffffffL;
        if (r.length() == 2 && r.endsWith("L")) {
            v = (old & 0xffffff00L) | (v & 0xffL);
        } else if (r.length() == 2 && r.endsWith("X")) {
            v = (old & 0xffff0000L) | (v & 0xffffL);
        }
        state.registers.put(base, v & 0xffffffffL);
    }

    private String regName(String operand) {
        String op = operand == null ? "" : operand.trim().toUpperCase();
        if (op.matches("E?[ABCD]X|E?[SD]I|E?[SB]P|ESP|AL|BL|CL|DL")) {
            return op;
        }
        return "";
    }

    private String registerBase(String reg) {
        if ("AL".equals(reg) || "AX".equals(reg)) {
            return "EAX";
        }
        if ("BL".equals(reg) || "BX".equals(reg)) {
            return "EBX";
        }
        if ("CL".equals(reg) || "CX".equals(reg)) {
            return "ECX";
        }
        if ("DL".equals(reg) || "DX".equals(reg)) {
            return "EDX";
        }
        return reg;
    }

    private MemoryOperandEx memoryOperandEx(String operand, MicroState state) {
        String op = operand == null ? "" : operand;
        int open = op.indexOf('[');
        int close = op.indexOf(']');
        if (open < 0 || close <= open) {
            return null;
        }
        String inner = op.substring(open + 1, close).replace(" ", "");
        if (inner.contains(":")) {
            return null;
        }
        String[] parts = inner.replace("-", "+-").split("\\+");
        String base = "";
        long offset = 0;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            long sign = 1;
            String p = part;
            if (p.startsWith("-")) {
                sign = -1;
                p = p.substring(1);
            }
            if (p.contains("*")) {
                String[] pair = p.split("\\*", 2);
                Long reg = readRegister(state, pair[0]);
                Long scale = parseLongLiteral(pair[1]);
                if (reg == null || scale == null) {
                    return null;
                }
                offset = (offset + sign * ((reg & 0xffffffffL) * scale)) & 0xffffffffL;
            } else if (regName(p).length() > 0) {
                if (base.isEmpty()) {
                    base = normalizeOperand(registerBase(regName(p)));
                } else {
                    Long reg = readRegister(state, p);
                    if (reg == null) {
                        return null;
                    }
                    offset = (offset + sign * (reg & 0xffffffffL)) & 0xffffffffL;
                }
            } else {
                Long imm = parseLongLiteral(p);
                if (imm == null) {
                    return null;
                }
                offset = (offset + sign * imm) & 0xffffffffL;
            }
        }
        return new MemoryOperandEx(base, (int)(offset & 0xffffffffL));
    }

    private Long readMemory(MicroState state, String base, int offset, int size) {
        Map<Integer, MemCell> cells = state.memory.get(base);
        long value = 0;
        for (int i = 0; i < size; i++) {
            int b = 0;
            if (cells != null && cells.containsKey(offset + i)) {
                b = cells.get(offset + i).value & 0xff;
            }
            value |= ((long)b) << (8 * i);
        }
        return value & 0xffffffffL;
    }

    private void writeMemory(
        MicroState state,
        String base,
        int offset,
        int size,
        long value,
        Instruction ins,
        int instructionIndex,
        boolean dynamic
    ) {
        Map<Integer, MemCell> cells = state.memory.computeIfAbsent(base, k -> new LinkedHashMap<Integer, MemCell>());
        for (int i = 0; i < size; i++) {
            MemCell cell = cells.computeIfAbsent(offset + i, k -> new MemCell());
            cell.value = (int)((value >> (8 * i)) & 0xff);
            cell.writeCount++;
            cell.dynamicWrite |= dynamic;
            cell.lastInstruction = ins.getAddress().toString() + " " + ins.toString();
            cell.lastInstructionIndex = instructionIndex;
            if (cell.firstInstruction.isEmpty()) {
                cell.firstInstruction = cell.lastInstruction;
                cell.firstInstructionIndex = instructionIndex;
            }
        }
    }

    private int instructionIndex(List<Instruction> instructions, Address target) {
        for (int i = 0; i < instructions.size(); i++) {
            if (instructions.get(i).getAddress().equals(target)) {
                return i;
            }
        }
        return -1;
    }

    private Address firstFlow(Instruction ins) {
        Address[] flows = ins.getFlows();
        return flows == null || flows.length == 0 ? null : flows[0];
    }

    private void writeSeedMemory(MicroState state, String base, int offset, int value) {
        Map<Integer, MemCell> cells = state.memory.computeIfAbsent(base, k -> new LinkedHashMap<Integer, MemCell>());
        MemCell cell = cells.computeIfAbsent(offset, k -> new MemCell());
        cell.value = value & 0xff;
        cell.writeCount = 1;
    }

    private void updateDecodeMutation(DecodeResult result, MicroState state, BufferSeed seed, int instructionIndex) {
        Map<Integer, MemCell> cells = state.memory.get(seed.base);
        if (cells == null) {
            return;
        }
        for (int offset = seed.minOffset; offset <= seed.maxOffset; offset++) {
            MemCell cell = cells.get(offset);
            if (cell != null && cell.dynamicWrite && cell.lastInstructionIndex == instructionIndex) {
                if (result.firstMutationIndex < 0) {
                    result.firstMutationIndex = instructionIndex;
                }
                result.lastMutationIndex = instructionIndex;
                return;
            }
        }
    }

    private boolean hasInterestingDecodedBytes(List<Integer> bytes) {
        List<Integer> trimmed = trimTrailingZeros(bytes);
        if (trimmed.size() < 3) {
            return false;
        }
        int printable = 0;
        for (Integer b : trimmed) {
            int v = b & 0xff;
            if (v == 0 || v == 9 || v == 10 || v == 13 || (v >= 0x20 && v <= 0x7e)) {
                printable++;
            }
        }
        return printable >= Math.max(3, (trimmed.size() * 3) / 4);
    }

    private List<Integer> trimTrailingZeros(List<Integer> bytes) {
        int end = bytes.size();
        while (end > 0 && (bytes.get(end - 1) & 0xff) == 0) {
            end--;
        }
        return new ArrayList<>(bytes.subList(0, end));
    }

    private List<Integer> trimDecodedBytes(List<Integer> bytes) {
        if (looksUtf16Le(bytes)) {
            int end = bytes.size();
            while (end >= 2 && (bytes.get(end - 1) & 0xff) == 0 && (bytes.get(end - 2) & 0xff) == 0) {
                end -= 2;
            }
            return new ArrayList<>(bytes.subList(0, end));
        }
        return trimTrailingZeros(bytes);
    }

    private boolean looksUtf16Le(List<Integer> bytes) {
        int pairs = bytes.size() / 2;
        if (pairs < 2) {
            return false;
        }
        int zeroHigh = 0;
        int printableLow = 0;
        for (int i = 0; i + 1 < bytes.size(); i += 2) {
            int low = bytes.get(i) & 0xff;
            int high = bytes.get(i + 1) & 0xff;
            if (high == 0) {
                zeroHigh++;
            }
            if (low >= 0x20 && low <= 0x7e) {
                printableLow++;
            }
        }
        return zeroHigh >= Math.max(2, (pairs * 3) / 4) && printableLow >= Math.max(2, pairs / 2);
    }

    private String instructionPreview(List<Instruction> instructions, int index) {
        if (index < 0 || index >= instructions.size()) {
            return "";
        }
        Instruction ins = instructions.get(index);
        return ins.getAddress().toString() + " " + ins.toString();
    }

    private List<Map<String, Object>> summarizeBlocks(List<Instruction> instructions, List<Map<String, Object>> events) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (instructions.isEmpty()) {
            return out;
        }
        int start = 0;
        int eventCursor = 0;
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            FlowType flow = ins.getFlowType();
            boolean ends = flow != null && (flow.isJump() || flow.isCall() || flow.isTerminal());
            if (!ends && i != instructions.size() - 1) {
                continue;
            }
            Map<String, Object> block = new LinkedHashMap<>();
            block.put("index", out.size());
            block.put("start", instructions.get(start).getAddress().toString());
            block.put("end", ins.getAddress().toString());
            block.put("instruction_count", i - start + 1);
            block.put("last_instruction", ins.getAddress().toString() + " " + ins.toString());
            block.put("flow_type", flow == null ? "" : flow.getName());
            block.put("flows", flows(ins));
            List<String> eventRefs = new ArrayList<>();
            while (eventCursor < events.size()) {
                String addr = (String)events.get(eventCursor).get("address");
                Address eventAddr = parseAddressOrNull(addr);
                if (eventAddr == null || eventAddr.compareTo(ins.getAddress()) > 0) {
                    break;
                }
                if (eventAddr.compareTo(instructions.get(start).getAddress()) >= 0) {
                    eventRefs.add(events.get(eventCursor).get("type") + "@" + addr);
                }
                eventCursor++;
            }
            block.put("events", eventRefs);
            out.add(block);
            start = i + 1;
        }
        return out;
    }

    private List<Map<String, Object>> collectLocalBuffers(List<Instruction> instructions, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            MemoryWrite first = immediateMemoryWrite(ins);
            if (first == null) {
                continue;
            }

            Map<Integer, Integer> bytesByOffset = new LinkedHashMap<>();
            List<String> writes = new ArrayList<>();
            int j = i;
            int matchingWrites = 0;
            while (j < instructions.size() && j <= i + 180 && bytesByOffset.size() < 512) {
                Instruction cur = instructions.get(j);
                MemoryWrite write = immediateMemoryWrite(cur);
                if (write == null || !write.base.equals(first.base)) {
                    if (matchingWrites >= 2) {
                        break;
                    }
                    j++;
                    continue;
                }
                for (int k = 0; k < write.size; k++) {
                    bytesByOffset.put(write.offset + k, (int)((write.value >> (8 * k)) & 0xff));
                }
                matchingWrites++;
                writes.add(cur.getAddress().toString() + " " + cur.toString() + " ; offset=0x" + Integer.toHexString(write.offset) + " size=" + write.size);
                j++;
            }
            if (matchingWrites < 2 || bytesByOffset.size() < 2 || !hasNonZeroByte(bytesByOffset)) {
                continue;
            }
            List<Integer> bytes = contiguousBytes(bytesByOffset);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("base", first.base);
            row.put("first_address", ins.getAddress().toString());
            row.put("write_count", matchingWrites);
            row.put("byte_count", bytes.size());
            row.put("min_offset", "0x" + Integer.toHexString(minOffset(bytesByOffset)));
            row.put("max_offset", "0x" + Integer.toHexString(maxOffset(bytesByOffset)));
            row.put("hex", bytesToHex(bytes));
            row.put("ascii_preview", bytesToAscii(bytes));
            row.put("utf16le_preview", bytesToUtf16Le(bytes));
            row.put("writes_preview", writes);
            row.put("nearby_calls", nearbyCalls(instructions, i, 96));
            out.add(row);
            i = Math.max(i, j - 1);
        }
        return out;
    }

    private List<String> collectConstants(List<Instruction> instructions, int limit) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Instruction ins : instructions) {
            for (String imm : immediates(ins.toString())) {
                Long value = parseLongLiteral(imm);
                if (value == null || value < 0x100) {
                    continue;
                }
                String hex = "0x" + Long.toUnsignedString(value, 16);
                if (seen.add(hex)) {
                    out.add(hex);
                    if (out.size() >= limit) {
                        return out;
                    }
                }
            }
        }
        return out;
    }

    private List<Instruction> clipAtStop(List<Instruction> instructions, Set<String> stops, Map<String, Object> env) {
        if (stops.isEmpty()) {
            return instructions;
        }
        List<Instruction> out = new ArrayList<>();
        for (Instruction ins : instructions) {
            out.add(ins);
            String addr = normalizeAddress(ins.getAddress().toString());
            if (stops.contains(addr)) {
                env.put("stopped_at", ins.getAddress().toString());
                break;
            }
        }
        return out;
    }

    private Map<String, Object> baseEvent(String type, Instruction ins) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("type", type);
        row.put("address", ins.getAddress().toString());
        row.put("mnemonic", ins.getMnemonicString());
        row.put("disassembly", ins.toString());
        return row;
    }

    private List<Map<String, Object>> recoverStackArgs(List<Instruction> instructions, int callIndex) {
        List<Map<String, Object>> args = new ArrayList<>();
        int ordinal = 0;
        for (int i = callIndex - 1; i >= 0 && i >= callIndex - 40; i--) {
            Instruction ins = instructions.get(i);
            String mnem = ins.getMnemonicString();
            if ("PUSH".equalsIgnoreCase(mnem)) {
                Map<String, Object> row = baseEvent("arg", ins);
                row.put("arg_index", ordinal++);
                row.put("source", operand(ins, 0));
                row.put("write_kind", "push");
                args.add(row);
                continue;
            }
            if ("MOV".equalsIgnoreCase(mnem)) {
                String dst = normalizeOperand(operand(ins, 0));
                if (dst.contains("[esp") || dst.contains("[rsp")) {
                    Map<String, Object> row = baseEvent("arg", ins);
                    row.put("arg_index", stackArgIndex(dst));
                    row.put("source", operand(ins, 1));
                    row.put("write_kind", "stack_store");
                    args.add(row);
                }
            }
        }
        return args;
    }

    private List<String> returnConsumers(List<Instruction> instructions, int callIndex) {
        List<String> out = new ArrayList<>();
        for (int i = callIndex + 1; i < instructions.size() && i <= callIndex + 18; i++) {
            Instruction ins = instructions.get(i);
            String text = ins.toString().toLowerCase();
            if (text.contains("eax") || text.contains("rax") || text.contains("ax")) {
                out.add(ins.getAddress().toString() + " " + ins.toString());
            }
            if (isCall(ins)) {
                break;
            }
        }
        return out;
    }

    private List<String> nearbyCalls(List<Instruction> instructions, int index, int radius) {
        List<String> out = new ArrayList<>();
        int start = Math.max(0, index - radius);
        int end = Math.min(instructions.size(), index + radius + 1);
        for (int i = start; i < end; i++) {
            Instruction ins = instructions.get(i);
            if (isCall(ins)) {
                out.add(ins.getAddress().toString() + " " + ins.toString() + " -> " + targetName(ins));
            }
        }
        return out;
    }

    private String nearbyPredicate(List<Instruction> instructions, int index) {
        for (int i = index - 1; i >= 0 && i >= index - 8; i--) {
            String m = instructions.get(i).getMnemonicString().toUpperCase();
            if (m.startsWith("CMP") || m.startsWith("TEST")) {
                return instructions.get(i).getAddress().toString() + " " + instructions.get(i).toString();
            }
        }
        return "";
    }

    private boolean isCall(Instruction ins) {
        FlowType flow = ins.getFlowType();
        return flow != null && flow.isCall();
    }

    private boolean isIndirectJump(Instruction ins) {
        String text = ins.toString().toLowerCase();
        return text.contains("[") || text.contains("ptr");
    }

    private boolean isStateWrite(String operand, String stateRegister) {
        if (stateRegister.isEmpty()) {
            return false;
        }
        String op = normalizeOperand(operand);
        return op.startsWith("[" + stateRegister + "+") || op.startsWith("[" + stateRegister + "-") || op.equals("[" + stateRegister + "]");
    }

    private boolean isInterestingImmediate(String text) {
        for (String imm : immediates(text)) {
            Long value = parseLongLiteral(imm);
            if (value != null && value >= 0x10000) {
                return true;
            }
        }
        return false;
    }

    private List<String> immediates(String text) {
        List<String> out = new ArrayList<>();
        Matcher m = IMM.matcher(text == null ? "" : text);
        while (m.find()) {
            String hex = m.group(1);
            String dec = m.group(2);
            out.add(hex != null ? "0x" + hex : dec);
        }
        return out;
    }

    private String targetName(Instruction ins) {
        Address[] flows = ins.getFlows();
        if (flows == null || flows.length == 0) {
            return "";
        }
        Function f = currentProgram.getFunctionManager().getFunctionAt(flows[0]);
        return f == null ? "" : safeFullName(f);
    }

    private String targetAddress(Instruction ins) {
        Address[] flows = ins.getFlows();
        return flows == null || flows.length == 0 ? "" : flows[0].toString();
    }

    private List<String> flows(Instruction ins) {
        List<String> out = new ArrayList<>();
        Address[] flows = ins.getFlows();
        if (flows != null) {
            for (Address flow : flows) {
                out.add(flow.toString());
            }
        }
        return out;
    }

    private String operand(Instruction ins, int index) {
        try {
            return ins.getDefaultOperandRepresentation(index);
        } catch (Exception ignored) {
            return "";
        }
    }

    private MemoryWrite immediateMemoryWrite(Instruction ins) {
        if (!"MOV".equalsIgnoreCase(ins.getMnemonicString())) {
            return null;
        }
        String op0 = operand(ins, 0);
        MemoryOperand mem = memoryOperand(op0);
        if (mem == null || mem.base.isEmpty()) {
            return null;
        }
        int size = operandWriteSize(op0);
        if (size <= 0 || size > 8) {
            return null;
        }
        Long value = parseImmediate(operand(ins, 1));
        if (value == null) {
            return null;
        }
        return new MemoryWrite(mem.base, mem.offset, size, value, op0);
    }

    private MemoryOperand memoryOperand(String operand) {
        String op = operand == null ? "" : operand;
        int open = op.indexOf('[');
        int close = op.indexOf(']');
        if (open >= 0 && close > open) {
            String inner = op.substring(open + 1, close).replace(" ", "");
            if (inner.contains("*") || inner.contains(":")) {
                return null;
            }
            int offset = 0;
            String base = inner;
            Matcher m = MEM_OPERAND_PATTERN.matcher(inner);
            if (m.matches()) {
                base = m.group(1);
                Long parsed = parseLongLiteral(m.group(3));
                if (parsed == null || parsed > Integer.MAX_VALUE) {
                    return null;
                }
                offset = parsed.intValue();
                if ("-".equals(m.group(2))) {
                    offset = -offset;
                }
            }
            return new MemoryOperand(normalizeOperand(base), offset);
        }
        return null;
    }

    private int operandWriteSize(String operand) {
        String op = operand == null ? "" : operand.toLowerCase();
        if (op.contains("qword") || op.contains(":8")) {
            return 8;
        }
        if (op.contains("dword") || op.contains(":4")) {
            return 4;
        }
        if (op.contains("word") || op.contains(":2")) {
            return 2;
        }
        if (op.contains("byte") || op.contains("char") || op.contains(":1")) {
            return 1;
        }
        return 0;
    }

    private Long parseImmediate(String operand) {
        Long last = null;
        for (String imm : immediates(operand)) {
            last = parseLongLiteral(imm);
        }
        return last;
    }

    private Long parseLongLiteral(String value) {
        try {
            String raw = value.toLowerCase();
            if (raw.startsWith("0x")) {
                return Long.parseUnsignedLong(raw.substring(2), 16);
            }
            return Long.parseLong(raw, 10);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private int stackArgIndex(String dst) {
        Matcher m = STACK_ARG_PATTERN.matcher(dst);
        long offset = 0;
        if (m.find()) {
            Long parsed = parseLongLiteral(m.group(1) != null ? "0x" + m.group(1) : m.group(2));
            if (parsed == null || parsed > 0x10000) {
                return -1;
            }
            offset = parsed;
        }
        return (int)(offset / currentProgram.getDefaultPointerSize());
    }

    private List<Instruction> instructionsIn(AddressSetView body, Address start, Address end, int maxInstructions) {
        AddressSet set = new AddressSet(body);
        if (start != null || end != null) {
            Address min = start == null ? body.getMinAddress() : start;
            Address max = end == null ? body.getMaxAddress() : end.previous();
            set = set.intersect(new AddressSet(min, max));
        }
        List<Instruction> out = new ArrayList<>();
        InstructionIterator iter = currentProgram.getListing().getInstructions(set, true);
        while (iter.hasNext() && out.size() < maxInstructions) {
            out.add(iter.next());
        }
        return out;
    }

    private List<Instruction> instructionsInRange(Address start, Address end, int maxInstructions) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator iter = currentProgram.getListing().getInstructions(new AddressSet(start, end.previous()), true);
        while (iter.hasNext() && out.size() < maxInstructions) {
            out.add(iter.next());
        }
        return out;
    }

    private Function resolveFunction(FunctionManager fm, String query) throws ResolutionException {
        Address addr = parseAddressOrNull(query);
        if (addr != null) {
            Function f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
            throw new ResolutionException("Function '" + query + "' not found.");
        }
        List<Function> exact = new ArrayList<>();
        List<Function> partial = new ArrayList<>();
        FunctionIterator iter = fm.getFunctions(true);
        String needle = query.toLowerCase();
        while (iter.hasNext()) {
            Function f = iter.next();
            String name = safeFullName(f).toLowerCase();
            if (name.equals(needle) || f.getName().equalsIgnoreCase(query)) {
                exact.add(f);
            } else if (name.contains(needle)) {
                partial.add(f);
            }
        }
        List<Function> matches = exact.isEmpty() ? partial : exact;
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.isEmpty()) {
            throw new ResolutionException("Function '" + query + "' not found.");
        }
        throw new ResolutionException("Function '" + query + "' is ambiguous (" + matches.size() + " matches).");
    }

    private Address parseAddressOrNull(String value) {
        try {
            String raw = trim(value);
            if (raw.isEmpty()) {
                return null;
            }
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                raw = raw.substring(2);
            }
            return currentProgram.getAddressFactory().getAddress(raw);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Address addDefaultRange(Address anchor) {
        try {
            return anchor.addNoWrap(0x800);
        } catch (Exception ignored) {
            return anchor;
        }
    }

    private Set<String> parseStopAddresses(String raw) {
        Set<String> out = new HashSet<>();
        for (String part : trim(raw).split(",")) {
            String s = normalizeAddress(part);
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    private String normalizeAddress(String raw) {
        String s = trim(raw).toLowerCase();
        if (s.startsWith("0x")) {
            s = s.substring(2);
        }
        while (s.length() > 1 && s.startsWith("0")) {
            s = s.substring(1);
        }
        return s;
    }

    private String normalizeOperand(String s) {
        return s == null ? "" : s.toLowerCase().replace(" ", "").replace("ptr", "");
    }

    private String normalizeRegister(String s) {
        return trim(s).toLowerCase();
    }

    private String safeFullName(Function f) {
        try {
            return f.getName(true);
        } catch (Exception ignored) {
            return f.getName();
        }
    }

    private String emptyDefault(String value, String defaultValue) {
        String s = trim(value);
        return s.isEmpty() ? defaultValue : s;
    }

    private String trim(String s) {
        return s == null ? "" : s.trim();
    }

    private int parseInt(String s, int defaultValue) {
        try {
            return Integer.parseInt(trim(s));
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private void writeEnvelope(String outputPath, Map<String, Object> env) throws Exception {
        Path path = Paths.get(outputPath);
        Files.createDirectories(path.getParent());
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(path))) {
            gson.toJson(env, writer);
        }
    }

    private boolean hasNonZeroByte(Map<Integer, Integer> bytesByOffset) {
        for (Integer b : bytesByOffset.values()) {
            if ((b & 0xff) != 0) {
                return true;
            }
        }
        return false;
    }

    private List<Integer> contiguousBytes(Map<Integer, Integer> bytesByOffset) {
        List<Integer> out = new ArrayList<>();
        int min = minOffset(bytesByOffset);
        int max = maxOffset(bytesByOffset);
        for (int offset = min; offset <= max; offset++) {
            out.add(bytesByOffset.getOrDefault(offset, 0));
        }
        return out;
    }

    private int minOffset(Map<Integer, Integer> bytesByOffset) {
        int min = Integer.MAX_VALUE;
        for (Integer offset : bytesByOffset.keySet()) {
            min = Math.min(min, offset);
        }
        return min == Integer.MAX_VALUE ? 0 : min;
    }

    private int maxOffset(Map<Integer, Integer> bytesByOffset) {
        int max = Integer.MIN_VALUE;
        for (Integer offset : bytesByOffset.keySet()) {
            max = Math.max(max, offset);
        }
        return max == Integer.MIN_VALUE ? 0 : max;
    }

    private String bytesToHex(List<Integer> bytes) {
        StringBuilder sb = new StringBuilder();
        for (Integer b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private String bytesToAscii(List<Integer> bytes) {
        StringBuilder sb = new StringBuilder();
        for (Integer b : bytes) {
            int v = b & 0xff;
            sb.append(v >= 0x20 && v <= 0x7e ? (char)v : '.');
        }
        return sb.toString();
    }

    private String bytesToUtf16Le(List<Integer> bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 1 < bytes.size(); i += 2) {
            int ch = (bytes.get(i) & 0xff) | ((bytes.get(i + 1) & 0xff) << 8);
            sb.append(ch >= 0x20 && ch <= 0x7e ? (char)ch : '.');
        }
        return sb.toString();
    }

    private static class MemoryOperand {
        final String base;
        final int offset;
        MemoryOperand(String base, int offset) {
            this.base = base;
            this.offset = offset;
        }
    }

    private static class MemoryOperandEx {
        final String base;
        final int offset;
        MemoryOperandEx(String base, int offset) {
            this.base = base;
            this.offset = offset;
        }
    }

    private static class MemoryWrite {
        final String base;
        final int offset;
        final int size;
        final long value;
        final String operand;
        MemoryWrite(String base, int offset, int size, long value, String operand) {
            this.base = base;
            this.offset = offset;
            this.size = size;
            this.value = value;
            this.operand = operand;
        }
    }

    private static class BufferSeed {
        final String base;
        final int firstIndex;
        int lastIndex;
        int minOffset = Integer.MAX_VALUE;
        int maxOffset = Integer.MIN_VALUE;
        final Map<Integer, Integer> bytesByOffset = new LinkedHashMap<>();
        final List<String> writes = new ArrayList<>();

        BufferSeed(String base, int firstIndex) {
            this.base = base;
            this.firstIndex = firstIndex;
            this.lastIndex = firstIndex;
        }

        void addWrite(MemoryWrite write, Instruction ins, int instructionIndex) {
            for (int i = 0; i < write.size; i++) {
                int offset = write.offset + i;
                bytesByOffset.put(offset, (int)((write.value >> (8 * i)) & 0xff));
                minOffset = Math.min(minOffset, offset);
                maxOffset = Math.max(maxOffset, offset);
            }
            lastIndex = instructionIndex;
            writes.add(ins.getAddress().toString() + " " + ins.toString()
                + " ; offset=0x" + Integer.toHexString(write.offset) + " size=" + write.size);
        }

    }

    private static class DecodeResult {
        final List<Integer> encodedBytes = new ArrayList<>();
        final List<Integer> decodedBytes = new ArrayList<>();
        int mutatedByteCount = 0;
        int differentByteCount = 0;
        int minOffset = 0;
        int maxOffset = 0;
        int firstMutationIndex = -1;
        int lastMutationIndex = -1;
        int stopIndex = -1;
        int branchCount = 0;

        void finish(MicroState state, BufferSeed seed) {
            Map<Integer, MemCell> cells = state.memory.get(seed.base);
            List<Integer> mutatedOffsets = new ArrayList<>();
            if (cells != null) {
                for (int offset = seed.minOffset; offset <= seed.maxOffset; offset++) {
                    MemCell cell = cells.get(offset);
                    if (cell != null && cell.dynamicWrite) {
                        mutatedOffsets.add(offset);
                    }
                }
            }
            if (mutatedOffsets.isEmpty()) {
                minOffset = seed.minOffset;
                maxOffset = seed.maxOffset;
            } else {
                mutatedOffsets.sort(Integer::compareTo);
                int bestStart = mutatedOffsets.get(0);
                int bestEnd = bestStart;
                int bestScore = -1;
                int cursor = 0;
                while (cursor < mutatedOffsets.size()) {
                    int start = mutatedOffsets.get(cursor);
                    int end = start;
                    cursor++;
                    while (cursor < mutatedOffsets.size() && mutatedOffsets.get(cursor) == end + 1) {
                        end = mutatedOffsets.get(cursor);
                        cursor++;
                    }
                    List<Integer> candidate = bytesForRange(cells, start, end);
                    int diff = differentByteCount(seed, candidate, start);
                    if (candidate.size() >= 3 && diff > 0 && hasInterestingStaticBytes(candidate)) {
                        int score = printableByteCount(candidate) * 4 + candidate.size();
                        if (score > bestScore) {
                            bestScore = score;
                            bestStart = start;
                            bestEnd = end;
                        }
                    }
                }
                if (bestScore < 0) {
                    bestStart = mutatedOffsets.get(0);
                    bestEnd = mutatedOffsets.get(mutatedOffsets.size() - 1);
                }
                minOffset = bestStart;
                maxOffset = bestEnd;
            }
            for (int offset = minOffset; offset <= maxOffset; offset++) {
                MemCell cell = cells == null ? null : cells.get(offset);
                int value = cell == null ? 0 : cell.value & 0xff;
                decodedBytes.add(value);
                if (cell != null && cell.dynamicWrite) {
                    mutatedByteCount++;
                }
                int encoded = seed.bytesByOffset.getOrDefault(offset, 0) & 0xff;
                encodedBytes.add(encoded);
                if (value != encoded) {
                    differentByteCount++;
                }
            }
            int firstChosenMutation = Integer.MAX_VALUE;
            int lastChosenMutation = -1;
            if (cells != null) {
                for (int offset = minOffset; offset <= maxOffset; offset++) {
                    MemCell cell = cells.get(offset);
                    if (cell != null && cell.dynamicWrite) {
                        firstChosenMutation = Math.min(firstChosenMutation, cell.lastInstructionIndex);
                        lastChosenMutation = Math.max(lastChosenMutation, cell.lastInstructionIndex);
                    }
                }
            }
            if (firstChosenMutation != Integer.MAX_VALUE) {
                firstMutationIndex = firstChosenMutation;
                lastMutationIndex = lastChosenMutation;
            }
        }

        private List<Integer> bytesForRange(Map<Integer, MemCell> cells, int start, int end) {
            List<Integer> out = new ArrayList<>();
            for (int offset = start; offset <= end; offset++) {
                MemCell cell = cells == null ? null : cells.get(offset);
                out.add(cell == null ? 0 : cell.value & 0xff);
            }
            return out;
        }

        private int differentByteCount(BufferSeed seed, List<Integer> bytes, int startOffset) {
            int out = 0;
            for (int i = 0; i < bytes.size(); i++) {
                int encoded = seed.bytesByOffset.getOrDefault(startOffset + i, 0) & 0xff;
                if ((bytes.get(i) & 0xff) != encoded) {
                    out++;
                }
            }
            return out;
        }

        private boolean hasInterestingStaticBytes(List<Integer> bytes) {
            List<Integer> trimmed = trimStaticTrailingZeros(bytes);
            if (trimmed.size() < 3) {
                return false;
            }
            return printableByteCount(trimmed) >= Math.max(3, (trimmed.size() * 3) / 4);
        }

        private int printableByteCount(List<Integer> bytes) {
            int out = 0;
            for (Integer b : bytes) {
                int v = b & 0xff;
                if (v == 0 || v == 9 || v == 10 || v == 13 || (v >= 0x20 && v <= 0x7e)) {
                    out++;
                }
            }
            return out;
        }

        private List<Integer> trimStaticTrailingZeros(List<Integer> bytes) {
            int end = bytes.size();
            while (end > 0 && (bytes.get(end - 1) & 0xff) == 0) {
                end--;
            }
            return new ArrayList<>(bytes.subList(0, end));
        }
    }

    private static class MicroState {
        final Map<String, Long> registers = new LinkedHashMap<>();
        final Map<String, Map<Integer, MemCell>> memory = new LinkedHashMap<>();
        boolean zf = false;
        boolean sf = false;
        boolean cf = false;
    }

    private static class MemCell {
        int value = 0;
        int writeCount = 0;
        boolean dynamicWrite = false;
        String firstInstruction = "";
        String lastInstruction = "";
        int firstInstructionIndex = Integer.MAX_VALUE;
        int lastInstructionIndex = -1;
    }

    private static class ResolutionException extends Exception {
        ResolutionException(String message) {
            super(message);
        }
    }
}
