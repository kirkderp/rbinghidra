// Recover hash-keyed dynamic dispatch/API tables from obfuscated loader code.
// Usage: <output_path> <table_count_global> <table_ptr_global> <builder_start> <builder_end>
//        <hash_function> <call_gate_global> <lookup_hashes_csv> <max_instructions> <limit>
//        [adapter_function] [hash_seed] [hash_multiplier] [candidate_names]
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
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

public class dynamic_dispatch_table extends GhidraScript {
    private static final String SCHEMA = "rbm.ghidra.dynamic_dispatch_table.v0";
    private static final Pattern MEM8_PATTERN = Pattern.compile(
        "(?i)\\[\\s*([a-z][a-z0-9]*)\\s*\\+\\s*([a-z][a-z0-9]*)\\s*\\*\\s*(?:0x)?8\\s*(?:\\+\\s*(0x[0-9a-f]+|\\d+))?\\s*\\]");
    private static final Pattern GLOBAL_PATTERN = Pattern.compile("(?i)0x[0-9a-f]{6,16}");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 10) {
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String countGlobalText = clean(args[1]);
        String ptrGlobalText = clean(args[2]);
        String builderStartText = clean(args[3]);
        String builderEndText = clean(args[4]);
        String hashFunctionText = clean(args[5]);
        String callGateGlobalText = clean(args[6]);
        String lookupHashesText = clean(args[7]);
        int maxInstructions = parseInt(args[8], 15000, 50000);
        int limit = parseInt(args[9], 100, 1000);
        String adapterFunctionText = args.length > 10 ? clean(args[10]) : "";
        String hashSeedText = args.length > 11 ? clean(args[11]) : "";
        String hashMultiplierText = args.length > 12 ? clean(args[12]) : "";
        String candidateNamesText = args.length > 13 ? args[13] : "";

        Address countGlobal = parseAddressOrNull(countGlobalText);
        Address ptrGlobal = parseAddressOrNull(ptrGlobalText);
        Address builderStart = parseAddressOrNull(builderStartText);
        Address builderEnd = parseAddressOrNull(builderEndText);
        Address hashFunction = parseAddressOrNull(hashFunctionText);
        Address callGateGlobal = parseAddressOrNull(callGateGlobalText);
        Address adapterFunction = parseAddressOrNull(adapterFunctionText);
        Set<Long> requestedHashes = parseHashSet(lookupHashesText);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("schema", SCHEMA);
        env.put("table_count_global", addrString(countGlobal));
        env.put("table_ptr_global", addrString(ptrGlobal));
        env.put("builder_start", addrString(builderStart));
        env.put("builder_end", addrString(builderEnd));
        env.put("hash_function", addrString(hashFunction));
        env.put("call_gate_global", addrString(callGateGlobal));
        env.put("adapter_function", addrString(adapterFunction));
        env.put("lookup_hashes_query", lookupHashesText);
        env.put("hash_seed", hashSeedText);
        env.put("hash_multiplier", hashMultiplierText);
        env.put("max_instructions", maxInstructions);
        env.put("limit", limit);
        env.put("table_shape", tableShape());
        env.put("resolution_error", "");

        if (countGlobal == null && ptrGlobal == null && builderStart == null && callGateGlobal == null) {
            env.put("resolution_error", "provide at least one global or builder address");
            writeEnvelope(outputPath, env);
            return;
        }

        List<Instruction> allInstructions = collectProgramInstructions(maxInstructions);
        List<Instruction> builderInstructions = collectBuilderInstructions(builderStart, builderEnd, maxInstructions);
        List<Instruction> combinedInstructions = new ArrayList<>(allInstructions);
        combinedInstructions.addAll(builderInstructions);

        env.put("builder_instruction_count", builderInstructions.size());
        env.put("global_references", collectGlobalReferences(combinedInstructions, countGlobal, ptrGlobal, callGateGlobal, limit));
        env.put("hash_calls", collectHashCalls(builderInstructions, hashFunction, limit));
        env.put("builder_hash_provenance", collectBuilderHashProvenance(builderInstructions, hashFunction, limit));
        env.put("table_inserts", collectTableInserts(builderInstructions, limit));
        env.put("table_insert_pairs", collectTableInsertPairs(builderInstructions, limit));
        env.put("table_lookups", collectTableLookups(allInstructions, requestedHashes, limit));
        env.put("adapter_calls", collectAdapterCalls(allInstructions, adapterFunction, limit));
        env.put("resolved_lookups", collectResolvedLookups(allInstructions, requestedHashes, adapterFunction, limit));
        env.put("name_resolution", resolveCandidateNames(requestedHashes, hashSeedText, hashMultiplierText, candidateNamesText));
        env.put("call_gate_references", collectCallGateReferences(combinedInstructions, callGateGlobal, limit));
        env.put("candidate_summary", candidateSummary(requestedHashes, allInstructions));
        env.put("unresolved_focus", unresolvedFocus(requestedHashes, allInstructions, adapterFunction, hashSeedText, hashMultiplierText, candidateNamesText, limit));
        env.put("notes", notes(countGlobal, ptrGlobal, hashFunction, callGateGlobal, adapterFunction));

        writeEnvelope(outputPath, env);
    }

    private Map<String, Object> tableShape() {
        Map<String, Object> shape = new LinkedHashMap<>();
        shape.put("entry_size_bytes", 8);
        shape.put("key_offset", 0);
        shape.put("value_offset", 4);
        shape.put("key_detection", "cmp/mov dword ptr [base + index*8]");
        shape.put("value_detection", "mov dword ptr [base + index*8 + 4]");
        return shape;
    }

    private List<Map<String, Object>> collectGlobalReferences(
        List<Instruction> instructions,
        Address countGlobal,
        Address ptrGlobal,
        Address callGateGlobal,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Instruction ins : instructions) {
            String text = normalize(ins.toString());
            String kind = "";
            if (countGlobal != null && (text.contains(normalize(countGlobal.toString())) || referencesAddress(ins, countGlobal))) {
                kind = "table_count_global";
            } else if (ptrGlobal != null && (text.contains(normalize(ptrGlobal.toString())) || referencesAddress(ins, ptrGlobal))) {
                kind = "table_ptr_global";
            } else if (callGateGlobal != null && (text.contains(normalize(callGateGlobal.toString())) || referencesAddress(ins, callGateGlobal))) {
                kind = "call_gate_global";
            }
            if (kind.isEmpty()) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("kind", kind);
            row.put("access_kind", isWriteToOperand(ins, 0) ? "write_or_update" : "read_or_use");
            row.put("function_name", functionNameAt(ins.getAddress()));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectHashCalls(
        List<Instruction> instructions,
        Address hashFunction,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (hashFunction == null) {
            return out;
        }
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins)) {
                continue;
            }
            String target = targetAddress(ins);
            if (!normalize(target).equals(normalize(hashFunction.toString()))) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("target_address", target);
            row.put("args_preview", recoverStackArgs(instructions, i));
            row.put("argument_provenance", argumentProvenance(instructions, i));
            row.put("return_consumers_preview", context(instructions, i + 1, Math.min(instructions.size(), i + 8)));
            row.put("context_before", context(instructions, Math.max(0, i - 12), i));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectBuilderHashProvenance(
        List<Instruction> instructions,
        Address hashFunction,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (hashFunction == null) {
            return out;
        }
        for (int i = 0; i < instructions.size() && out.size() < limit; i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins) || !targetMatches(ins, hashFunction)) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("function_name", functionNameAt(ins.getAddress()));
            row.put("target_address", targetAddress(ins));
            row.put("args_preview", recoverStackArgs(instructions, i));
            row.put("argument_provenance", argumentProvenance(instructions, i));
            row.put("return_value_flow", registerWritesAfter(instructions, i, "EAX", 12));
            row.put("nearby_insert_pairs_after", insertPairsAfter(instructions, i, 80));
            row.put("nearby_stub_value_markers", stubValueMarkers(instructions, Math.max(0, i - 40), Math.min(instructions.size(), i + 80)));
            row.put("context_before", context(instructions, Math.max(0, i - 16), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 16)));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> collectTableInserts(List<Instruction> instructions, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            TableMem mem = tableMem(ins, 0);
            if (mem == null || !"MOV".equalsIgnoreCase(ins.getMnemonicString())) {
                continue;
            }
            if (mem.offset != 0 && mem.offset != 4) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("entry_field", mem.offset == 0 ? "key" : "value");
            row.put("entry_size_bytes", 8);
            row.put("base_register", mem.base);
            row.put("index_register", mem.index);
            row.put("entry_offset", mem.offset);
            row.put("source", operand(ins, 1));
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 6)));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectTableInsertPairs(List<Instruction> instructions, int limit) {
        return insertPairsAfter(instructions, 0, instructions.size(), limit);
    }

    private List<Map<String, Object>> insertPairsAfter(List<Instruction> instructions, int index, int window) {
        return insertPairsAfter(instructions, index, window, 8);
    }

    private List<Map<String, Object>> insertPairsAfter(List<Instruction> instructions, int index, int window, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        int end = Math.min(instructions.size(), index + window);
        for (int i = Math.max(0, index); i < end && out.size() < limit; i++) {
            Instruction keyIns = instructions.get(i);
            TableMem keyMem = tableMem(keyIns, 0);
            if (keyMem == null || keyMem.offset != 0 || !"MOV".equalsIgnoreCase(keyIns.getMnemonicString())) {
                continue;
            }
            for (int j = i + 1; j < end && j <= i + 8; j++) {
                Instruction valueIns = instructions.get(j);
                TableMem valueMem = tableMem(valueIns, 0);
                if (valueMem == null || valueMem.offset != 4 || !"MOV".equalsIgnoreCase(valueIns.getMnemonicString())) {
                    continue;
                }
                if (!valueMem.base.equalsIgnoreCase(keyMem.base) || !valueMem.index.equalsIgnoreCase(keyMem.index)) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("key_write", baseInstruction(keyIns));
                row.put("key_source", operand(keyIns, 1));
                row.put("value_write", baseInstruction(valueIns));
                row.put("value_source", operand(valueIns, 1));
                row.put("base_register", keyMem.base);
                row.put("index_register", keyMem.index);
                row.put("distance_instructions", j - i);
                row.put("context_before", context(instructions, Math.max(0, i - 6), i));
                row.put("context_between", context(instructions, i + 1, j));
                row.put("context_after", context(instructions, j + 1, Math.min(instructions.size(), j + 5)));
                out.add(row);
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectTableLookups(
        List<Instruction> instructions,
        Set<Long> requestedHashes,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            TableMem left = tableMem(ins, 0);
            TableMem right = tableMem(ins, 1);
            if (!"CMP".equalsIgnoreCase(ins.getMnemonicString()) || (left == null && right == null)) {
                continue;
            }
            Long imm = left != null ? immediateFromOperand(ins, 1) : immediateFromOperand(ins, 0);
            if (imm == null) {
                continue;
            }
            if (!requestedHashes.isEmpty() && !requestedHashes.contains(imm & 0xffffffffL)) {
                continue;
            }
            TableMem mem = left != null ? left : right;
            if (mem.offset != 0) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("hash", hex32(imm));
            row.put("base_register", mem.base);
            row.put("index_register", mem.index);
            row.put("function_name", functionNameAt(ins.getAddress()));
            row.put("value_loads_after", valueLoadsAfter(instructions, i, mem.base, mem.index));
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 10)));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectAdapterCalls(
        List<Instruction> instructions,
        Address adapterFunction,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (adapterFunction == null) {
            return out;
        }
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            if (!isCall(ins) || !targetMatches(ins, adapterFunction)) {
                continue;
            }
            Map<String, Object> row = adapterCallRow(instructions, i);
            row.put("context_before", context(instructions, Math.max(0, i - 10), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 5)));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectResolvedLookups(
        List<Instruction> instructions,
        Set<Long> requestedHashes,
        Address adapterFunction,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            TableMem left = tableMem(ins, 0);
            TableMem right = tableMem(ins, 1);
            if (!"CMP".equalsIgnoreCase(ins.getMnemonicString()) || (left == null && right == null)) {
                continue;
            }
            Long imm = left != null ? immediateFromOperand(ins, 1) : immediateFromOperand(ins, 0);
            if (imm == null) {
                continue;
            }
            long hash = imm & 0xffffffffL;
            if (!requestedHashes.isEmpty() && !requestedHashes.contains(hash)) {
                continue;
            }
            TableMem mem = left != null ? left : right;
            if (mem.offset != 0) {
                continue;
            }

            Map<String, Object> row = baseInstruction(ins);
            row.put("hash", hex32(hash));
            row.put("base_register", mem.base);
            row.put("index_register", mem.index);
            row.put("function_name", functionNameAt(ins.getAddress()));
            List<Map<String, Object>> valueLoads = valueLoadRowsAfter(instructions, i, mem.base, mem.index);
            row.put("value_loads_after", valueLoads);

            int searchStart = i;
            if (!valueLoads.isEmpty()) {
                searchStart = instructionIndexAt(instructions, (String)valueLoads.get(0).get("address"), i);
            }
            Map<String, Object> adapterCall = findAdapterCallAfter(instructions, searchStart, adapterFunction, 24);
            row.put("adapter_call", adapterCall == null ? new LinkedHashMap<String, Object>() : adapterCall);
            row.put("has_adapter_call", adapterCall != null);
            row.put("context_before", context(instructions, Math.max(0, i - 8), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 18)));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private List<Map<String, Object>> collectCallGateReferences(
        List<Instruction> instructions,
        Address callGateGlobal,
        int limit
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (callGateGlobal == null) {
            return out;
        }
        String gate = normalize(callGateGlobal.toString());
        for (int i = 0; i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            String text = normalize(ins.toString());
            if (!text.contains(gate) && !referencesAddress(ins, callGateGlobal)) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("access_kind", isWriteToOperand(ins, 0) ? "write_or_update" : "read_or_use");
            row.put("is_indirect_call", isCall(ins) && referencesAddress(ins, callGateGlobal));
            row.put("function_name", functionNameAt(ins.getAddress()));
            row.put("context_before", context(instructions, Math.max(0, i - 6), i));
            row.put("context_after", context(instructions, i + 1, Math.min(instructions.size(), i + 6)));
            out.add(row);
            if (out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    private Map<String, Object> candidateSummary(Set<Long> requestedHashes, List<Instruction> instructions) {
        Map<String, Object> summary = new LinkedHashMap<>();
        List<String> requested = new ArrayList<>();
        List<String> observed = new ArrayList<>();
        for (Long value : requestedHashes) {
            requested.add(hex32(value));
        }
        Set<Long> observedSet = new HashSet<>();
        for (Instruction ins : instructions) {
            if (!"CMP".equalsIgnoreCase(ins.getMnemonicString())) {
                continue;
            }
            if (tableMem(ins, 0) == null && tableMem(ins, 1) == null) {
                continue;
            }
            TableMem left = tableMem(ins, 0);
            TableMem right = tableMem(ins, 1);
            if (left == null && right == null) {
                continue;
            }
            Long imm = left != null ? immediateFromOperand(ins, 1) : immediateFromOperand(ins, 0);
            if (imm != null) {
                observedSet.add(imm & 0xffffffffL);
            }
        }
        for (Long value : observedSet) {
            observed.add(hex32(value));
        }
        summary.put("requested_hashes", requested);
        summary.put("observed_lookup_hashes", observed);
        summary.put("diagnostic", "This pass does not brute-force external DLL export corpora; use rows here to decide whether the value is a raw export hash, transformed key, or non-export dispatch value.");
        return summary;
    }

    private Map<String, Object> resolveCandidateNames(
        Set<Long> requestedHashes,
        String hashSeedText,
        String hashMultiplierText,
        String candidateNamesText
    ) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Map<String, Object>> matches = new ArrayList<>();
        List<String> unmatched = new ArrayList<>();
        List<String> names = candidateNames(candidateNamesText);
        Long seed = parseNumericOrNull(hashSeedText);
        Long multiplier = parseNumericOrNull(hashMultiplierText);

        out.put("algorithm", "fnv1a32_bytes");
        out.put("candidate_count", names.size());
        out.put("matches", matches);
        out.put("unmatched_hashes", unmatched);
        if (requestedHashes.isEmpty()) {
            out.put("diagnostic", "No lookup_hashes were provided, so candidate names were not resolved.");
            return out;
        }
        if (seed == null || multiplier == null || names.isEmpty()) {
            out.put("diagnostic", "Provide hash_seed, hash_multiplier, and candidate_names to resolve names in this pass.");
            for (Long hash : requestedHashes) {
                unmatched.add(hex32(hash));
            }
            return out;
        }

        Set<Long> matched = new HashSet<>();
        for (String name : names) {
            long hashed = fnv1a32(name, seed, multiplier);
            if (!requestedHashes.contains(hashed)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("hash", hex32(hashed));
            row.put("name", name);
            row.put("seed", hex32(seed));
            row.put("multiplier", hex32(multiplier));
            matches.add(row);
            matched.add(hashed);
        }
        for (Long hash : requestedHashes) {
            if (!matched.contains(hash)) {
                unmatched.add(hex32(hash));
            }
        }
        out.put("diagnostic", unmatched.isEmpty() ? "All requested hashes matched candidate_names." : "Some requested hashes did not match candidate_names.");
        return out;
    }

    private Map<String, Object> unresolvedFocus(
        Set<Long> requestedHashes,
        List<Instruction> instructions,
        Address adapterFunction,
        String hashSeedText,
        String hashMultiplierText,
        String candidateNamesText,
        int limit
    ) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> resolution = resolveCandidateNames(requestedHashes, hashSeedText, hashMultiplierText, candidateNamesText);
        Set<String> unmatched = new HashSet<>();
        Object unmatchedObj = resolution.get("unmatched_hashes");
        if (unmatchedObj instanceof List<?>) {
            for (Object item : (List<?>)unmatchedObj) {
                unmatched.add(String.valueOf(item));
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        if (requestedHashes.isEmpty()) {
            out.put("rows", rows);
            out.put("diagnostic", "No focused hashes were provided.");
            return out;
        }
        for (Map<String, Object> row : collectResolvedLookups(instructions, requestedHashes, adapterFunction, limit)) {
            String hash = String.valueOf(row.get("hash"));
            if (!unmatched.isEmpty() && !unmatched.contains(hash)) {
                continue;
            }
            Map<String, Object> focus = new LinkedHashMap<>();
            focus.put("hash", hash);
            focus.put("lookup_address", row.get("address"));
            focus.put("function_name", row.get("function_name"));
            focus.put("value_loads_after", row.get("value_loads_after"));
            focus.put("adapter_call", row.get("adapter_call"));
            focus.put("context_before", row.get("context_before"));
            focus.put("context_after", row.get("context_after"));
            rows.add(focus);
        }
        out.put("rows", rows);
        out.put("diagnostic", "Focused rows are unresolved by the supplied candidate names and include the nearest table-value load plus adapter call, when found.");
        return out;
    }

    private List<String> notes(Address countGlobal, Address ptrGlobal, Address hashFunction, Address callGateGlobal, Address adapterFunction) {
        List<String> notes = new ArrayList<>();
        if (countGlobal == null) {
            notes.add("table_count_global was omitted or invalid; global count references are not classified");
        }
        if (ptrGlobal == null) {
            notes.add("table_ptr_global was omitted or invalid; pointer global references are not classified");
        }
        if (hashFunction == null) {
            notes.add("hash_function was omitted or invalid; hash call rows are not collected");
        }
        if (callGateGlobal == null) {
            notes.add("call_gate_global was omitted or invalid; call-gate rows are not collected");
        }
        if (adapterFunction == null) {
            notes.add("adapter_function was omitted or invalid; resolved lookup rows will not include adapter call correlation");
        }
        return notes;
    }

    private List<Instruction> collectProgramInstructions(int maxInstructions) {
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && out.size() < maxInstructions) {
            out.add(it.next());
        }
        return out;
    }

    private List<Instruction> collectBuilderInstructions(Address start, Address end, int maxInstructions) {
        if (start == null) {
            return collectProgramInstructions(maxInstructions);
        }
        Address scanEnd = end == null ? start.add(0x1000) : end;
        List<Instruction> out = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(new AddressSet(start, scanEnd), true);
        while (it.hasNext() && out.size() < maxInstructions) {
            out.add(it.next());
        }
        return out;
    }

    private List<Map<String, Object>> recoverStackArgs(List<Instruction> instructions, int callIndex) {
        List<Map<String, Object>> args = new ArrayList<>();
        int argIndex = 0;
        for (int i = callIndex - 1; i >= 0 && i >= callIndex - 18 && args.size() < 8; i--) {
            Instruction ins = instructions.get(i);
            String mnemonic = ins.getMnemonicString();
            if ("PUSH".equalsIgnoreCase(mnemonic)) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("arg_index", argIndex++);
                row.put("address", ins.getAddress().toString());
                row.put("source", operand(ins, 0));
                row.put("disassembly", ins.toString());
                args.add(row);
            }
        }
        return args;
    }

    private List<Map<String, Object>> argumentProvenance(List<Instruction> instructions, int callIndex) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> arg : recoverStackArgs(instructions, callIndex)) {
            String source = String.valueOf(arg.get("source"));
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("arg_index", arg.get("arg_index"));
            row.put("source", source);
            row.put("push_address", arg.get("address"));
            String register = sourceRegister(source);
            row.put("source_register", register);
            row.put("recent_writes", register.isEmpty()
                ? new ArrayList<Map<String, Object>>()
                : registerWritesBefore(instructions, callIndex, register, 16));
            row.put("memory_base_register", memoryBaseRegister(source));
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> registerWritesBefore(
        List<Instruction> instructions,
        int index,
        String register,
        int window
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = index - 1; i >= 0 && i >= index - window && out.size() < 6; i--) {
            Instruction ins = instructions.get(i);
            if (!register.equalsIgnoreCase(operand(ins, 0))) {
                continue;
            }
            String mnemonic = ins.getMnemonicString();
            if (!("MOV".equalsIgnoreCase(mnemonic)
                || "LEA".equalsIgnoreCase(mnemonic)
                || "XOR".equalsIgnoreCase(mnemonic)
                || "ADD".equalsIgnoreCase(mnemonic)
                || "SUB".equalsIgnoreCase(mnemonic))) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("distance_instructions", index - i);
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> registerWritesAfter(
        List<Instruction> instructions,
        int index,
        String register,
        int window
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = index + 1; i < instructions.size() && i <= index + window && out.size() < 8; i++) {
            Instruction ins = instructions.get(i);
            String mnemonic = ins.getMnemonicString();
            String dst = operand(ins, 0);
            String src = operand(ins, 1);
            if (!register.equalsIgnoreCase(dst) && !register.equalsIgnoreCase(src)) {
                continue;
            }
            if (!("MOV".equalsIgnoreCase(mnemonic)
                || "XOR".equalsIgnoreCase(mnemonic)
                || "OR".equalsIgnoreCase(mnemonic)
                || "TEST".equalsIgnoreCase(mnemonic)
                || "CMP".equalsIgnoreCase(mnemonic)
                || "PUSH".equalsIgnoreCase(mnemonic)
                || "JZ".equalsIgnoreCase(mnemonic)
                || "JNZ".equalsIgnoreCase(mnemonic))) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("distance_instructions", i - index);
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> stubValueMarkers(List<Instruction> instructions, int start, int end) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = start; i < end && out.size() < 16; i++) {
            Instruction ins = instructions.get(i);
            String text = normalize(ins.toString());
            if (!(text.contains("[ebp+-0x1c]") || text.contains("[ebp-0x1c]") || text.contains("[ebp + -0x1c]"))) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("role_hint", isWriteToOperand(ins, 0) ? "candidate_value_update" : "candidate_value_read");
            out.add(row);
        }
        return out;
    }

    private String sourceRegister(String text) {
        if (text == null) {
            return "";
        }
        String s = text.trim().toUpperCase();
        if (s.matches("E?[ABCD]X|E?[SD]I|E?[SB]P|R[0-9A-Z]+")) {
            return s;
        }
        return "";
    }

    private String memoryBaseRegister(String text) {
        if (text == null) {
            return "";
        }
        Matcher m = Pattern.compile("(?i)\\[\\s*([a-z][a-z0-9]*)").matcher(text);
        if (m.find()) {
            return m.group(1).toUpperCase();
        }
        return "";
    }

    private Map<String, Object> adapterCallRow(List<Instruction> instructions, int callIndex) {
        Instruction ins = instructions.get(callIndex);
        Map<String, Object> row = baseInstruction(ins);
        List<Map<String, Object>> args = recoverStackArgs(instructions, callIndex);
        row.put("target_address", targetAddress(ins));
        row.put("function_name", functionNameAt(ins.getAddress()));
        row.put("args_preview", args);
        row.put("arg_bytes", adapterArgBytes(args));
        row.put("syscall_number_source", args.isEmpty() ? "" : args.get(0).get("source"));
        row.put("syscall_args_preview", syscallArgsPreview(args));
        return row;
    }

    private Object adapterArgBytes(List<Map<String, Object>> args) {
        for (Map<String, Object> arg : args) {
            Object idx = arg.get("arg_index");
            if (!(idx instanceof Integer) || ((Integer)idx) != 1) {
                continue;
            }
            Long parsed = parseNumericOrNull(String.valueOf(arg.get("source")));
            return parsed == null ? arg.get("source") : parsed;
        }
        return "";
    }

    private List<Map<String, Object>> syscallArgsPreview(List<Map<String, Object>> args) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> arg : args) {
            Object idx = arg.get("arg_index");
            if (!(idx instanceof Integer) || ((Integer)idx) < 2) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("syscall_arg_index", ((Integer)idx) - 2);
            row.put("source", arg.get("source"));
            row.put("push_address", arg.get("address"));
            row.put("disassembly", arg.get("disassembly"));
            out.add(row);
        }
        return out;
    }

    private Map<String, Object> findAdapterCallAfter(
        List<Instruction> instructions,
        int startIndex,
        Address adapterFunction,
        int window
    ) {
        if (adapterFunction == null) {
            return null;
        }
        for (int i = startIndex + 1; i < instructions.size() && i <= startIndex + window; i++) {
            Instruction ins = instructions.get(i);
            if (isCall(ins) && targetMatches(ins, adapterFunction)) {
                Map<String, Object> row = adapterCallRow(instructions, i);
                row.put("distance_instructions", i - startIndex);
                return row;
            }
        }
        return null;
    }

    private List<Map<String, Object>> valueLoadRowsAfter(
        List<Instruction> instructions,
        int index,
        String base,
        String idx
    ) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = index + 1; i < instructions.size() && i <= index + 16 && out.size() < 4; i++) {
            Instruction ins = instructions.get(i);
            TableMem mem = tableMem(ins, 1);
            if (mem == null || mem.offset != 4) {
                continue;
            }
            if (!mem.base.equalsIgnoreCase(base) || !mem.index.equalsIgnoreCase(idx)) {
                continue;
            }
            Map<String, Object> row = baseInstruction(ins);
            row.put("destination", operand(ins, 0));
            row.put("source", operand(ins, 1));
            row.put("distance_instructions", i - index);
            out.add(row);
        }
        return out;
    }

    private List<String> valueLoadsAfter(List<Instruction> instructions, int index, String base, String idx) {
        List<String> out = new ArrayList<>();
        String needle = normalize("[" + base + " + " + idx + "*0x8 + 0x4");
        String needle2 = normalize("[" + base + " + " + idx + "*8 + 4");
        for (int i = index + 1; i < instructions.size() && i <= index + 16 && out.size() < 4; i++) {
            Instruction ins = instructions.get(i);
            String text = normalize(ins.toString());
            if (text.contains(needle) || text.contains(needle2)) {
                out.add(ins.getAddress().toString() + " " + ins.toString());
            }
        }
        return out;
    }

    private int instructionIndexAt(List<Instruction> instructions, String address, int defaultValue) {
        if (address == null || address.isEmpty()) {
            return defaultValue;
        }
        for (int i = Math.max(0, defaultValue); i < instructions.size(); i++) {
            if (instructions.get(i).getAddress().toString().equalsIgnoreCase(address)) {
                return i;
            }
        }
        return defaultValue;
    }

    private TableMem tableMem(Instruction ins, int operandIndex) {
        String op = operand(ins, operandIndex);
        Matcher m = MEM8_PATTERN.matcher(op);
        if (!m.find()) {
            return null;
        }
        int offset = 0;
        if (m.group(3) != null && !m.group(3).isEmpty()) {
            offset = (int)parseNumeric(m.group(3));
        }
        return new TableMem(m.group(1).toUpperCase(), m.group(2).toUpperCase(), offset);
    }

    private Long immediateFromOperand(Instruction ins, int operandIndex) {
        if (operandIndex >= ins.getNumOperands()) {
            return null;
        }
        for (Object obj : ins.getOpObjects(operandIndex)) {
            if (obj instanceof Scalar) {
                return ((Scalar)obj).getUnsignedValue() & 0xffffffffL;
            }
        }
        return null;
    }

    private boolean isWriteToOperand(Instruction ins, int operandIndex) {
        if (ins.getNumOperands() <= operandIndex) {
            return false;
        }
        String mnemonic = ins.getMnemonicString();
        String op = operand(ins, operandIndex);
        return ("MOV".equalsIgnoreCase(mnemonic) || mnemonic.toUpperCase().startsWith("XCHG"))
            && op.contains("[");
    }

    private boolean isCall(Instruction ins) {
        FlowType flow = ins.getFlowType();
        return flow != null && flow.isCall();
    }

    private boolean targetMatches(Instruction ins, Address target) {
        if (target == null) {
            return false;
        }
        String expected = normalizeAddress(target.toString());
        String actual = normalizeAddress(targetAddress(ins));
        if (!actual.isEmpty() && actual.equals(expected)) {
            return true;
        }
        return normalizeAddress(operand(ins, 0)).contains(expected);
    }

    private String targetAddress(Instruction ins) {
        Reference[] refs = ins.getReferencesFrom();
        for (Reference ref : refs) {
            if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                return ref.getToAddress().toString();
            }
        }
        Matcher m = GLOBAL_PATTERN.matcher(ins.toString());
        if (m.find()) {
            return m.group();
        }
        return "";
    }

    private boolean referencesAddress(Instruction ins, Address address) {
        if (address == null) {
            return false;
        }
        for (Reference ref : ins.getReferencesFrom()) {
            if (address.equals(ref.getToAddress())) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> baseInstruction(Instruction ins) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("address", ins.getAddress().toString());
        row.put("mnemonic", ins.getMnemonicString());
        row.put("disassembly", ins.toString());
        row.put("operand0", operand(ins, 0));
        row.put("operand1", operand(ins, 1));
        return row;
    }

    private String operand(Instruction ins, int index) {
        if (index >= ins.getNumOperands()) {
            return "";
        }
        try {
            return ins.getDefaultOperandRepresentation(index);
        } catch (Exception err) {
            return "";
        }
    }

    private List<String> context(List<Instruction> instructions, int start, int end) {
        List<String> out = new ArrayList<>();
        for (int i = start; i < end && i < instructions.size(); i++) {
            Instruction ins = instructions.get(i);
            out.add(ins.getAddress().toString() + " " + ins.toString());
        }
        return out;
    }

    private String functionNameAt(Address address) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(address);
        return f == null ? "" : f.getName(true);
    }

    private Address parseAddressOrNull(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        String s = text.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            s = s.substring(2);
        }
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(s);
        } catch (Exception err) {
            return null;
        }
    }

    private Set<Long> parseHashSet(String text) {
        Set<Long> out = new HashSet<>();
        if (text == null || text.trim().isEmpty()) {
            return out;
        }
        for (String part : text.split("[,;\\s]+")) {
            if (part.trim().isEmpty()) {
                continue;
            }
            out.add(parseNumeric(part.trim()) & 0xffffffffL);
        }
        return out;
    }

    private long parseNumeric(String text) {
        String s = text.trim().toLowerCase();
        if (s.startsWith("0x")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    private Long parseNumericOrNull(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        try {
            return parseNumeric(text) & 0xffffffffL;
        } catch (Exception err) {
            return null;
        }
    }

    private int parseInt(String text, int defaultValue, int cap) {
        try {
            int parsed = Integer.parseInt(text.trim());
            if (parsed <= 0) {
                return defaultValue;
            }
            return Math.min(parsed, cap);
        } catch (Exception err) {
            return defaultValue;
        }
    }

    private String clean(String text) {
        return text == null ? "" : text.trim();
    }

    private String addrString(Address address) {
        return address == null ? "" : address.toString();
    }

    private String normalize(String text) {
        return text == null ? "" : text.toLowerCase().replace(" ", "");
    }

    private String normalizeAddress(String text) {
        String s = normalize(text).replace("0x", "");
        while (s.length() > 1 && s.startsWith("0")) {
            s = s.substring(1);
        }
        return s;
    }

    private String hex32(long value) {
        return String.format("0x%08x", value & 0xffffffffL);
    }

    private List<String> candidateNames(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) {
            return out;
        }
        Set<String> seen = new HashSet<>();
        for (String part : text.split("[,;\\s]+")) {
            String name = part.trim();
            if (name.isEmpty() || seen.contains(name)) {
                continue;
            }
            out.add(name);
            seen.add(name);
        }
        return out;
    }

    private long fnv1a32(String name, long seed, long multiplier) {
        long h = seed & 0xffffffffL;
        byte[] bytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (byte b : bytes) {
            h ^= (long)b & 0xffL;
            h = (h * multiplier) & 0xffffffffL;
        }
        return h & 0xffffffffL;
    }

    private void writeEnvelope(String outputPath, Map<String, Object> env) throws Exception {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Path path = Paths.get(outputPath);
        Files.createDirectories(path.getParent());
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(path))) {
            writer.print(gson.toJson(env));
        }
    }

    private static class TableMem {
        final String base;
        final String index;
        final int offset;

        TableMem(String base, String index, int offset) {
            this.base = base;
            this.index = index;
            this.offset = offset;
        }
    }
}
