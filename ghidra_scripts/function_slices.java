// Cheap function-local slicing for callsites, field references, local buffers, indirect jumps,
// shallow field lineage, and jump-table fanout field summaries.
// Usage: <output_path> <mode> <name_or_address> <query> <range_start> <range_end> <limit>
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class function_slices extends GhidraScript {
    private static final String SCHEMA = "rbm.ghidra.function_slices.v0";
    private static final int CONTEXT_BEFORE = 18;
    private static final int CONTEXT_AFTER = 12;
    private static final Pattern IMM = Pattern.compile("(?i)\\b0x([0-9a-f]{1,16})\\b|\\b(\\d{1,20})\\b");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 7) {
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String mode = emptyDefault(args[1], "all");
        String nameOrAddress = args[2];
        String query = args[3] == null ? "" : args[3].trim();
        String rangeStart = args[4] == null ? "" : args[4].trim();
        String rangeEnd = args[5] == null ? "" : args[5].trim();
        int limit = parseLimit(args[6]);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("schema", SCHEMA);
        env.put("mode", mode);
        env.put("query", query);
        env.put("function_query", nameOrAddress);
        env.put("range_start", rangeStart);
        env.put("range_end", rangeEnd);
        env.put("limit", limit);
        env.put("resolved_address", "");
        env.put("resolved_function_name", "");
        env.put("scope_kind", "");
        env.put("scope_warning", "");
        env.put("instruction_count", 0);
        env.put("callsite_count", 0);
        env.put("field_reference_count", 0);
        env.put("local_buffer_count", 0);
        env.put("indirect_jump_count", 0);
        env.put("lineage_count", 0);
        env.put("target_count", 0);
        env.put("callsites", new ArrayList<Map<String, Object>>());
        env.put("field_references", new ArrayList<Map<String, Object>>());
        env.put("local_buffers", new ArrayList<Map<String, Object>>());
        env.put("indirect_jumps", new ArrayList<Map<String, Object>>());
        env.put("lineages", new ArrayList<Map<String, Object>>());
        env.put("targets", new ArrayList<Map<String, Object>>());
        env.put("resolution_error", "");

        if ("table_lineage".equals(mode)) {
            int entryCount = parsePositiveInt(rangeStart, 64, 512);
            int maxInstructions = parsePositiveInt(rangeEnd, 160, 1200);
            env.put("function_query", "");
            env.put("range_start", "");
            env.put("range_end", "");
            env.put("table_address", nameOrAddress);
            env.put("root_operand", query);
            env.put("entry_count", entryCount);
            env.put("max_instructions", maxInstructions);
            env.put("scope_kind", "jump_table");
            Address tableAddress = parseAddressOrNull(nameOrAddress);
            if (tableAddress != null) {
                env.put("resolved_address", tableAddress.toString());
            }
            List<Map<String, Object>> targets = collectJumpTableLineages(nameOrAddress, query, entryCount, maxInstructions, limit);
            env.put("target_count", targets.size());
            env.put("targets", targets);
            writeEnvelope(outputPath, env);
            return;
        }

        Address start = parseAddressOrNull(rangeStart);
        Address end = parseAddressOrNull(rangeEnd);
        List<Instruction> instructions;
        try {
            Function function = resolveFunction(currentProgram.getFunctionManager(), nameOrAddress);
            env.put("resolved_address", function.getEntryPoint().toString());
            env.put("resolved_function_name", safeFullName(function));
            env.put("scope_kind", "function");
            instructions = instructionsIn(function.getBody(), start, end);
        } catch (ResolutionException err) {
            Address anchor = start == null ? parseAddressOrNull(nameOrAddress) : start;
            if (anchor == null) {
                env.put("resolution_error", err.getMessage());
                writeEnvelope(outputPath, env);
                return;
            }
            Address scanEnd = end == null ? addDefaultRange(anchor) : end;
            env.put("resolved_address", anchor.toString());
            env.put("resolved_function_name", "");
            env.put("scope_kind", "address_range");
            env.put("scope_warning", "no containing Ghidra function; scanned address range");
            env.put("range_start", anchor.toString());
            env.put("range_end", scanEnd.toString());
            instructions = instructionsInRange(anchor, scanEnd);
        }
        env.put("instruction_count", instructions.size());

        if ("all".equals(mode) || "callsites".equals(mode)) {
            List<Map<String, Object>> callsites = collectCallsites(instructions, query, limit);
            env.put("callsite_count", callsites.size());
            env.put("callsites", callsites);
        }
        if ("all".equals(mode) || "fields".equals(mode)) {
            List<Map<String, Object>> refs = collectFieldRefs(instructions, query, limit);
            env.put("field_reference_count", refs.size());
            env.put("field_references", refs);
        }
        if ("all".equals(mode) || "buffers".equals(mode)) {
            List<Map<String, Object>> buffers = collectLocalBuffers(instructions, query, limit);
            env.put("local_buffer_count", buffers.size());
            env.put("local_buffers", buffers);
        }
        if ("all".equals(mode) || "indirect".equals(mode)) {
            List<Map<String, Object>> jumps = collectIndirectJumps(instructions, limit);
            env.put("indirect_jump_count", jumps.size());
            env.put("indirect_jumps", jumps);
        }
        if ("all".equals(mode) || "lineage".equals(mode)) {
            List<Map<String, Object>> lineages = collectLineages(instructions, query, limit);
            env.put("lineage_count", lineages.size());
            env.put("lineages", lineages);
        }

        writeEnvelope(outputPath, env);
    }

    private List<Map<String, Object>> collectJumpTableLineages(
        String tableAddress,
        String rootQuery,
        int entryCount,
        int maxInstructions,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        Address table = parseAddressOrNull(tableAddress);
        if (table == null || rootQuery == null || rootQuery.trim().isEmpty()) {
            return out;
        }

        Map<String, List<Integer>> indicesByTarget = new LinkedHashMap<>();
        int pointerSize = currentProgram.getDefaultPointerSize();
        for (int i = 0; i < entryCount; i++) {
            try {
                Address entry = table.addNoWrap((long)i * pointerSize);
                long raw = pointerSize == 8
                    ? currentProgram.getMemory().getLong(entry)
                    : Integer.toUnsignedLong(currentProgram.getMemory().getInt(entry));
                if (raw == 0 || raw == 1) {
                    continue;
                }
                Address target = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(Long.toHexString(raw));
                if (target == null || !currentProgram.getMemory().contains(target)) {
                    continue;
                }
                String key = target.toString();
                indicesByTarget.computeIfAbsent(key, k -> new ArrayList<Integer>()).add(i);
            } catch (Exception ignored) {
            }
        }

        for (Map.Entry<String, List<Integer>> entry : indicesByTarget.entrySet()) {
            if (out.size() >= limit) {
                break;
            }
            Address target = parseAddressOrNull(entry.getKey());
            if (target == null) {
                continue;
            }
            List<Instruction> instructions = instructionsFrom(target, maxInstructions);
            Map<String, Object> row = summarizeLineageTarget(target, entry.getValue(), instructions, rootQuery, limit);
            out.add(row);
        }
        return out;
    }

    private Map<String, Object> summarizeLineageTarget(
        Address target,
        List<Integer> entryIndices,
        List<Instruction> instructions,
        String rootQuery,
        int limit
    ) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("target_address", target.toString());
        row.put("entry_indices", entryIndices);
        row.put("instruction_count", instructions.size());
        row.put("field_offsets", new ArrayList<String>());
        row.put("events", new ArrayList<Map<String, Object>>());
        row.put("calls_preview", callsPreview(instructions, 16));
        row.put("terminal_jumps_preview", terminalJumpsPreview(instructions, 16));

        String needle = normalize(rootQuery);
        Map<String, String> registerTags = new LinkedHashMap<>();
        Map<String, Integer> offsets = new LinkedHashMap<>();
        List<Map<String, Object>> events = new ArrayList<>();

        for (int i = 0; i < instructions.size() && events.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            String mnemonic = ins.getMnemonicString();
            String op0 = operand(ins, 0);
            String op1 = operand(ins, 1);
            String dstReg = normalizeRegisterName(op0);
            String srcReg = normalizeRegisterName(op1);
            boolean assignedTrackedValue = false;

            if ("MOV".equalsIgnoreCase(mnemonic) && isRegister(dstReg) && normalize(op1).contains(needle)) {
                registerTags.put(dstReg, "root");
                Map<String, Object> evt = baseInstruction(ins);
                evt.put("event", "root_load");
                evt.put("root_operand", op1);
                evt.put("tracked_register", dstReg);
                events.add(evt);
                assignedTrackedValue = true;
            }

            MemoryOperand mem0 = memoryOperand(op0);
            MemoryOperand mem1 = memoryOperand(op1);
            if (mem0 != null && registerTags.containsKey(mem0.base)) {
                Map<String, Object> evt = baseInstruction(ins);
                evt.put("event", "field_store_or_update");
                evt.put("base_register", mem0.base);
                evt.put("base_tag", registerTags.get(mem0.base));
                evt.put("field_offset", mem0.offset);
                evt.put("field_offset_hex", formatSignedHex(mem0.offset));
                evt.put("source", op1);
                events.add(evt);
                offsets.put(formatSignedHex(mem0.offset), mem0.offset);
            }
            if (mem1 != null && registerTags.containsKey(mem1.base)) {
                String tag = registerTags.get(mem1.base) + formatSignedHex(mem1.offset);
                Map<String, Object> evt = baseInstruction(ins);
                evt.put("event", "field_read");
                evt.put("base_register", mem1.base);
                evt.put("base_tag", registerTags.get(mem1.base));
                evt.put("field_offset", mem1.offset);
                evt.put("field_offset_hex", formatSignedHex(mem1.offset));
                evt.put("destination", op0);
                evt.put("value_tag", tag);
                events.add(evt);
                offsets.put(formatSignedHex(mem1.offset), mem1.offset);
                if ("MOV".equalsIgnoreCase(mnemonic) && isRegister(dstReg)) {
                    registerTags.put(dstReg, tag);
                    assignedTrackedValue = true;
                }
            } else if ("MOV".equalsIgnoreCase(mnemonic) && isRegister(dstReg) && registerTags.containsKey(srcReg)) {
                registerTags.put(dstReg, registerTags.get(srcReg));
                assignedTrackedValue = true;
                Map<String, Object> evt = baseInstruction(ins);
                evt.put("event", "register_alias");
                evt.put("destination_register", dstReg);
                evt.put("source_register", srcReg);
                evt.put("value_tag", registerTags.get(srcReg));
                events.add(evt);
            } else if (isCall(ins)) {
                List<Map<String, Object>> args = recoverStackArgs(instructions, i);
                List<Map<String, Object>> taggedArgs = new ArrayList<>();
                for (Map<String, Object> arg : args) {
                    String argSource = normalizeRegisterName(String.valueOf(arg.get("source")));
                    if (registerTags.containsKey(argSource)) {
                        Map<String, Object> tagged = new LinkedHashMap<>(arg);
                        tagged.put("value_tag", registerTags.get(argSource));
                        taggedArgs.add(tagged);
                    }
                }
                if (!taggedArgs.isEmpty()) {
                    Map<String, Object> evt = baseInstruction(ins);
                    evt.put("event", "call_with_tracked_arg");
                    evt.put("target_name", targetName(ins));
                    evt.put("target_address", targetAddress(ins));
                    evt.put("tracked_args", taggedArgs);
                    events.add(evt);
                }
            }

            if (!assignedTrackedValue && isRegister(dstReg) && registerTags.containsKey(dstReg) && clobbersTrackedRegister(ins, dstReg)) {
                registerTags.remove(dstReg);
            }
        }

        row.put("field_offsets", new ArrayList<String>(offsets.keySet()));
        row.put("events", events);
        row.put("event_count", events.size());
        return row;
    }

    private List<Map<String, Object>> collectCallsites(List<Instruction> instructions, String query, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        String needle = normalize(query);
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins)) {
                continue;
            }
            String targetName = targetName(ins);
            String targetAddress = targetAddress(ins);
            String address = ins.getAddress().toString();
            String hay = normalize(address + " 0x" + address + " " + targetName + " " + targetAddress + " " + ins.toString());
            if (!needle.isEmpty() && !hay.contains(needle)) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("target_name", targetName);
            row.put("target_address", targetAddress);
            List<Map<String, Object>> args = recoverStackArgs(instructions, i);
            row.put("args_preview", args);
            Map<String, Object> adapter = detectSizePrefixedAdapter(args);
            if (adapter != null) {
                row.put("adapter_preview", adapter);
            }
            row.put("return_consumers_preview", returnConsumers(instructions, i));
            row.put("context_before", context(instructions, Math.max(0, i - CONTEXT_BEFORE), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 1 + CONTEXT_AFTER)));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> collectFieldRefs(List<Instruction> instructions, String query, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        String needle = normalize(query);
        if (needle.isEmpty()) {
            return out;
        }
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            String op0 = operand(ins, 0);
            String op1 = operand(ins, 1);
            String all = normalize(ins.toString() + " " + op0 + " " + op1);
            if (!all.contains(needle)) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("access_kind", normalize(op0).contains(needle) ? "write_or_update" : "read_or_use");
            row.put("operand0", op0);
            row.put("operand1", op1);
            row.put("nearby_calls", nearbyCalls(instructions, i, 24));
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 9)));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> collectLocalBuffers(List<Instruction> instructions, String query, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        String needle = normalize(query);
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            MemoryWrite first = immediateMemoryWrite(ins);
            if (first == null) {
                continue;
            }
            if (!needle.isEmpty() && !normalize(first.base + " " + first.operand + " " + ins.toString()).contains(needle)) {
                continue;
            }

            Map<Integer, Integer> bytesByOffset = new LinkedHashMap<>();
            List<String> writes = new ArrayList<>();
            int j = i;
            int matchingWrites = 0;
            while (j < instructions.size() && j <= i + 160 && bytesByOffset.size() < 256) {
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
            if (matchingWrites < 2 || bytesByOffset.size() < 2) {
                continue;
            }
            List<Integer> bytes = contiguousBytes(bytesByOffset);
            if (!hasNonZeroByte(bytes)) {
                continue;
            }
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

    private List<Map<String, Object>> collectIndirectJumps(List<Instruction> instructions, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Instruction ins : instructions) {
            if (out.size() >= limit) {
                break;
            }
            FlowType flow = ins.getFlowType();
            if (flow == null || !flow.isJump()) {
                continue;
            }
            String text = ins.toString();
            if (!text.contains("[") && !text.toLowerCase().contains("ptr")) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("operand0", operand(ins, 0));
            row.put("flows", flows(ins));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> collectLineages(List<Instruction> instructions, String query, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        String needle = normalize(query);
        if (needle.isEmpty()) {
            return out;
        }
        int scanLimit = Math.max(80, Math.min(240, limit * 24));
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction root = instructions.get(i);
            String dst = normalizeRegisterName(operand(root, 0));
            String src = normalize(operand(root, 1));
            if (!"MOV".equalsIgnoreCase(root.getMnemonicString()) || !isRegister(dst) || !src.contains(needle)) {
                continue;
            }

            Map<String, String> registerTags = new LinkedHashMap<>();
            registerTags.put(dst, "root");
            List<Map<String, Object>> events = new ArrayList<>();
            Map<String, Integer> offsets = new LinkedHashMap<>();

            Map<String, Object> rootEvent = baseInstruction(root);
            rootEvent.put("event", "root_load");
            rootEvent.put("root_operand", operand(root, 1));
            rootEvent.put("tracked_register", dst);
            events.add(rootEvent);

            for (int j = i + 1; j < instructions.size() && j <= i + scanLimit && events.size() < limit; j++) {
                Instruction ins = instructions.get(j);
                String mnemonic = ins.getMnemonicString();
                String op0 = operand(ins, 0);
                String op1 = operand(ins, 1);
                String dstReg = normalizeRegisterName(op0);
                String srcReg = normalizeRegisterName(op1);
                boolean assignedTrackedValue = false;

                MemoryOperand mem0 = memoryOperand(op0);
                MemoryOperand mem1 = memoryOperand(op1);
                if (mem0 != null && registerTags.containsKey(mem0.base)) {
                    Map<String, Object> row = baseInstruction(ins);
                    row.put("event", "field_store_or_update");
                    row.put("base_register", mem0.base);
                    row.put("base_tag", registerTags.get(mem0.base));
                    row.put("field_offset", mem0.offset);
                    row.put("field_offset_hex", formatSignedHex(mem0.offset));
                    row.put("source", op1);
                    String srcTag = registerTags.get(srcReg);
                    if (srcTag != null) {
                        row.put("source_tag", srcTag);
                    }
                    row.put("nearby_calls", nearbyCalls(instructions, j, 18));
                    events.add(row);
                    offsets.put(formatSignedHex(mem0.offset), mem0.offset);
                }
                if (mem1 != null && registerTags.containsKey(mem1.base)) {
                    String tag = registerTags.get(mem1.base) + formatSignedHex(mem1.offset);
                    Map<String, Object> row = baseInstruction(ins);
                    row.put("event", "field_read");
                    row.put("base_register", mem1.base);
                    row.put("base_tag", registerTags.get(mem1.base));
                    row.put("field_offset", mem1.offset);
                    row.put("field_offset_hex", formatSignedHex(mem1.offset));
                    row.put("destination", op0);
                    row.put("value_tag", tag);
                    row.put("nearby_calls", nearbyCalls(instructions, j, 18));
                    events.add(row);
                    offsets.put(formatSignedHex(mem1.offset), mem1.offset);
                    if ("MOV".equalsIgnoreCase(mnemonic) && isRegister(dstReg)) {
                        registerTags.put(dstReg, tag);
                        assignedTrackedValue = true;
                    }
                } else if ("MOV".equalsIgnoreCase(mnemonic) && isRegister(dstReg) && registerTags.containsKey(srcReg)) {
                    registerTags.put(dstReg, registerTags.get(srcReg));
                    assignedTrackedValue = true;
                    Map<String, Object> row = baseInstruction(ins);
                    row.put("event", "register_alias");
                    row.put("destination_register", dstReg);
                    row.put("source_register", srcReg);
                    row.put("value_tag", registerTags.get(srcReg));
                    events.add(row);
                } else if ("PUSH".equalsIgnoreCase(mnemonic) && registerTags.containsKey(srcReg)) {
                    Map<String, Object> row = baseInstruction(ins);
                    row.put("event", "push_tracked_value");
                    row.put("source_register", srcReg);
                    row.put("value_tag", registerTags.get(srcReg));
                    row.put("nearby_calls", nearbyCalls(instructions, j, 8));
                    events.add(row);
                } else if (isCall(ins)) {
                    List<Map<String, Object>> args = recoverStackArgs(instructions, j);
                    List<Map<String, Object>> taggedArgs = new ArrayList<>();
                    for (Map<String, Object> arg : args) {
                        String argSource = normalizeRegisterName(String.valueOf(arg.get("source")));
                        if (registerTags.containsKey(argSource)) {
                            Map<String, Object> tagged = new LinkedHashMap<>(arg);
                            tagged.put("value_tag", registerTags.get(argSource));
                            taggedArgs.add(tagged);
                        }
                    }
                    if (!taggedArgs.isEmpty()) {
                        Map<String, Object> row = baseInstruction(ins);
                        row.put("event", "call_with_tracked_arg");
                        row.put("target_name", targetName(ins));
                        row.put("target_address", targetAddress(ins));
                        row.put("tracked_args", taggedArgs);
                        events.add(row);
                    }
                }

                if (!assignedTrackedValue && isRegister(dstReg) && registerTags.containsKey(dstReg) && clobbersTrackedRegister(ins, dstReg)) {
                    registerTags.remove(dstReg);
                }
                if (registerTags.isEmpty()) {
                    break;
                }
            }

            Map<String, Object> lineage = baseInstruction(root);
            lineage.put("root_operand", operand(root, 1));
            lineage.put("root_register", dst);
            lineage.put("event_count", events.size());
            lineage.put("field_offsets", new ArrayList<String>(offsets.keySet()));
            lineage.put("events", events);
            out.add(lineage);
        }
        return out;
    }

    private List<Map<String, Object>> recoverStackArgs(List<Instruction> instructions, int callIndex) {
        List<Map<String, Object>> args = new ArrayList<>();
        int ordinal = 0;
        int pointerSize = currentProgram.getDefaultPointerSize();
        for (int i = callIndex - 1; i >= 0 && i >= callIndex - 40; i--) {
            Instruction ins = instructions.get(i);
            String mnem = ins.getMnemonicString();
            if ("PUSH".equalsIgnoreCase(mnem)) {
                String source = operand(ins, 0);
                Map<String, Object> row = baseInstruction(ins);
                row.put("arg_index", ordinal);
                row.put("source", source);
                row.put("write_kind", "push");
                row.put("call_sp_delta_before_push", formatSignedHex(pointerSize * (ordinal + 1)));
                Map<String, Object> sourceStackRef = normalizedSourceStackRef(source, ordinal, pointerSize);
                if (sourceStackRef != null) {
                    row.put("source_stack_ref", sourceStackRef);
                }
                args.add(row);
                ordinal++;
                continue;
            }
            if ("MOV".equalsIgnoreCase(mnem)) {
                String dst = normalize(operand(ins, 0));
                if (dst.contains("[esp") || dst.contains("[rsp")) {
                    Map<String, Object> row = baseInstruction(ins);
                    row.put("arg_index", stackArgIndex(dst));
                    row.put("source", operand(ins, 1));
                    row.put("write_kind", "stack_store");
                    args.add(row);
                }
            }
        }
        int pushBytes = ordinal * pointerSize;
        for (Map<String, Object> arg : args) {
            arg.put("arg_push_count_before_call", ordinal);
            arg.put("arg_push_bytes_before_call", formatSignedHex(pushBytes));
            Object refObj = arg.get("source_stack_ref");
            if (refObj instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> ref = (Map<String, Object>)refObj;
                Object callOffsetObj = ref.get("call_sp_offset");
                if (callOffsetObj instanceof Number) {
                    int setupOffset = ((Number)callOffsetObj).intValue() - pushBytes;
                    ref.put("setup_sp_offset", setupOffset);
                    ref.put("setup_sp_offset_hex", formatSignedHex(setupOffset));
                }
            }
        }
        return args;
    }

    private Map<String, Object> detectSizePrefixedAdapter(List<Map<String, Object>> args) {
        Map<String, Object> functionPtr = argByIndex(args, 0);
        Map<String, Object> argSizeRow = argByIndex(args, 1);
        if (functionPtr == null || argSizeRow == null) {
            return null;
        }
        Long argSize = parseImmediate(stringField(argSizeRow.get("source")));
        if (argSize == null) {
            return null;
        }
        int pointerSize = currentProgram.getDefaultPointerSize();
        if (argSize <= 0 || argSize > 0x100 || (argSize % pointerSize) != 0) {
            return null;
        }
        int nativeArgCount = (int)(argSize / pointerSize);
        List<Map<String, Object>> nativeArgs = new ArrayList<>();
        for (int i = 0; i < nativeArgCount; i++) {
            Map<String, Object> sourceArg = argByIndex(args, i + 2);
            if (sourceArg == null) {
                break;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("native_arg_index", i);
            row.put("source", sourceArg.get("source"));
            row.put("address", sourceArg.get("address"));
            row.put("disassembly", sourceArg.get("disassembly"));
            if (sourceArg.containsKey("source_stack_ref")) {
                row.put("source_stack_ref", sourceArg.get("source_stack_ref"));
            }
            nativeArgs.add(row);
        }
        if (nativeArgs.size() < nativeArgCount) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", "size_prefixed_stack_adapter_candidate");
        out.put("function_pointer_source", functionPtr.get("source"));
        out.put("arg_size", argSize);
        out.put("arg_size_hex", "0x" + Long.toHexString(argSize));
        out.put("native_arg_count", nativeArgCount);
        out.put("native_args_preview", nativeArgs);
        return out;
    }

    private Map<String, Object> argByIndex(List<Map<String, Object>> args, int index) {
        for (Map<String, Object> arg : args) {
            Object value = arg.get("arg_index");
            if (value instanceof Number && ((Number)value).intValue() == index) {
                return arg;
            }
        }
        return null;
    }

    private Map<String, Object> normalizedSourceStackRef(String source, int argIndex, int pointerSize) {
        MemoryOperand mem = memoryOperand(source);
        if (mem == null || (!"esp".equals(mem.base) && !"rsp".equals(mem.base))) {
            return null;
        }
        int callOffset = mem.offset + pointerSize * (argIndex + 1);
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("base", mem.base);
        ref.put("operand_offset", mem.offset);
        ref.put("operand_offset_hex", formatSignedHex(mem.offset));
        ref.put("call_sp_offset", callOffset);
        ref.put("call_sp_offset_hex", formatSignedHex(callOffset));
        return ref;
    }

    private String stringField(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private String formatSignedHex(int value) {
        if (value < 0) {
            return "-0x" + Integer.toHexString(-value);
        }
        return "0x" + Integer.toHexString(value);
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

    private List<String> callsPreview(List<Instruction> instructions, int limit) {
        List<String> out = new ArrayList<>();
        for (Instruction ins : instructions) {
            if (out.size() >= limit) {
                break;
            }
            if (isCall(ins)) {
                out.add(ins.getAddress().toString() + " " + ins.toString() + " -> " + targetName(ins));
            }
        }
        return out;
    }

    private List<String> terminalJumpsPreview(List<Instruction> instructions, int limit) {
        List<String> out = new ArrayList<>();
        for (Instruction ins : instructions) {
            if (out.size() >= limit) {
                break;
            }
            FlowType flow = ins.getFlowType();
            if (flow == null) {
                continue;
            }
            if (flow.isJump() || flow.isTerminal()) {
                out.add(ins.getAddress().toString() + " " + ins.toString());
            }
        }
        return out;
    }

    private Map<String, Object> baseInstruction(Instruction ins) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("address", ins.getAddress().toString());
        row.put("mnemonic", ins.getMnemonicString());
        row.put("disassembly", ins.toString());
        return row;
    }

    private boolean isCall(Instruction ins) {
        FlowType flow = ins.getFlowType();
        return flow != null && flow.isCall();
    }

    private boolean clobbersTrackedRegister(Instruction ins, String register) {
        String mnemonic = ins.getMnemonicString();
        if (!("MOV".equalsIgnoreCase(mnemonic) || "LEA".equalsIgnoreCase(mnemonic) ||
              "XOR".equalsIgnoreCase(mnemonic) || "SUB".equalsIgnoreCase(mnemonic) ||
              "ADD".equalsIgnoreCase(mnemonic) || "POP".equalsIgnoreCase(mnemonic))) {
            return false;
        }
        String dst = normalizeRegisterName(operand(ins, 0));
        if (!register.equals(dst)) {
            return false;
        }
        String op1 = normalize(operand(ins, 1));
        return !op1.contains(register);
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

    private List<String> context(List<Instruction> instructions, int start, int end) {
        List<String> out = new ArrayList<>();
        for (int i = start; i < end; i++) {
            Instruction ins = instructions.get(i);
            out.add(ins.getAddress().toString() + " " + ins.toString());
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

    private String normalize(String s) {
        return s == null ? "" : s.toLowerCase().replace(" ", "").replace("ptr", "");
    }

    private String normalizeRegisterName(String s) {
        String reg = normalize(s);
        if (reg.startsWith("dword") || reg.startsWith("qword") || reg.startsWith("word") || reg.startsWith("byte")) {
            return "";
        }
        return reg;
    }

    private boolean isRegister(String s) {
        return s.matches("(?i)(e?[abcd]x|e?[sd]i|e?[sb]p|r[0-9]+[dwb]?|r[abcd]x|r[sd]i|r[sb]p|[abcd][lh])");
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
            Matcher m = Pattern.compile("(?i)^(.+?)([+-])(0x[0-9a-f]+|\\d+)$").matcher(inner);
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
            return new MemoryOperand(normalize(base), offset);
        }
        return null;
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
        if (operand == null) {
            return null;
        }
        Matcher m = IMM.matcher(operand);
        Long last = null;
        while (m.find()) {
            String hex = m.group(1);
            String dec = m.group(2);
            last = hex != null ? Long.parseUnsignedLong(hex, 16) : Long.parseLong(dec, 10);
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
        Matcher m = Pattern.compile("\\+0x([0-9a-f]+)|\\+(\\d+)").matcher(dst);
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

    private boolean hasNonZeroByte(List<Integer> bytes) {
        for (Integer b : bytes) {
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

    private List<Instruction> instructionsIn(AddressSetView body, Address start, Address end) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            Address addr = ins.getAddress();
            if (start != null && addr.compareTo(start) < 0) {
                continue;
            }
            if (end != null && addr.compareTo(end) >= 0) {
                continue;
            }
            out.add(ins);
        }
        return out;
    }

    private List<Instruction> instructionsInRange(Address start, Address end) {
        List<Instruction> out = new ArrayList<>();
        AddressSet set = new AddressSet(start, end);
        InstructionIterator it = currentProgram.getListing().getInstructions(set, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) >= 0) {
                break;
            }
            out.add(ins);
            if (out.size() >= 4096) {
                break;
            }
        }
        return out;
    }

    private List<Instruction> instructionsFrom(Address start, int maxInstructions) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        while (it.hasNext() && out.size() < maxInstructions) {
            Instruction ins = it.next();
            if (!currentProgram.getMemory().contains(ins.getAddress())) {
                break;
            }
            out.add(ins);
            FlowType flow = ins.getFlowType();
            if (flow != null && flow.isTerminal()) {
                break;
            }
        }
        return out;
    }

    private Address addDefaultRange(Address start) {
        try {
            return start.addNoWrap(0x800);
        } catch (Exception ignored) {
            return start;
        }
    }

    private Address parseAddressOrNull(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        try {
            AddressFactory factory = currentProgram.getAddressFactory();
            String cleaned = value.trim().replaceFirst("^(0x|0X)", "");
            return factory.getDefaultAddressSpace().getAddress(cleaned);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Function resolveFunction(FunctionManager fm, String query) throws ResolutionException {
        Address address = parseAddressOrNull(query);
        if (address != null) {
            Function f = fm.getFunctionContaining(address);
            if (f != null) {
                return f;
            }
        }
        List<Function> exact = new ArrayList<>();
        List<Function> partial = new ArrayList<>();
        String needle = query.toLowerCase();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String name = safeFullName(f).toLowerCase();
            if (name.equals(needle) || f.getName().equalsIgnoreCase(query)) {
                exact.add(f);
            } else if (name.contains(needle)) {
                partial.add(f);
            }
        }
        if (exact.size() == 1) {
            return exact.get(0);
        }
        if (exact.size() > 1) {
            throw new ResolutionException("ambiguous function query: " + query);
        }
        if (partial.size() == 1) {
            return partial.get(0);
        }
        if (partial.size() > 1) {
            throw new ResolutionException("ambiguous function query: " + query);
        }
        throw new ResolutionException("function not found: " + query);
    }

    private String safeFullName(Function f) {
        try {
            return f.getName(true);
        } catch (Exception ignored) {
            return f.getName();
        }
    }

    private int parseLimit(String raw) {
        try {
            int value = Integer.parseInt(raw);
            return value <= 0 ? 50 : Math.min(value, 500);
        } catch (Exception ignored) {
            return 50;
        }
    }

    private int parsePositiveInt(String raw, int defaultValue, int max) {
        try {
            int value = Integer.parseInt(raw);
            if (value <= 0) {
                return defaultValue;
            }
            return Math.min(value, max);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private String emptyDefault(String value, String defaultValue) {
        return value == null || value.trim().isEmpty() ? defaultValue : value.trim();
    }

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws Exception {
        Path path = Paths.get(outputPath);
        Files.createDirectories(path.getParent());
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            writer.println(new GsonBuilder().disableHtmlEscaping().create().toJson(envelope));
        }
    }

    private static class ResolutionException extends Exception {
        ResolutionException(String message) {
            super(message);
        }
    }

    private static class MemoryOperand {
        final String base;
        final int offset;

        MemoryOperand(String base, int offset) {
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
}
