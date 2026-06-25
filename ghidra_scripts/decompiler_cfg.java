// Extract a decompiler-level basic-block CFG for a function and write a JSON envelope to the path
// passed as the first script argument.
// Usage: <output_path> <name_or_address> [simplification_style] [include_ops]
// name_or_address is parsed as an address first (AddressFactory.getAddress after stripping a
// leading 0x/0X), then resolved via FunctionManager.getFunctionContaining. On address-path
// failure it falls back to case-insensitive exact-then-partial match against the fully-qualified
// function name (Function.getName(true)).
// simplification_style defaults to "decompile". Supported values mirror Ghidra's
// DecompInterface.setSimplificationStyle: decompile, normalize, register, firstpass, paramid.
// Blocks are walked via HighFunction.getBasicBlocks() and edges are walked via PcodeBlockBasic.getOut(i).
// Always exits 0 and writes a valid envelope; lookup failures populate resolution_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class decompiler_cfg extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompiler_cfg.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int MNEMONIC_PREVIEW_LIMIT = 8;
    private static final int VARNODE_PREVIEW_LIMIT = 6;
    private static final int ADDRESS_PREVIEW_LIMIT = 6;
    private static final int CALL_CONTEXT_PREVIEW_LIMIT = 10;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[decompiler_cfg] missing args; expected <output_path> <name_or_address> [simplification_style] [include_ops]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;
        boolean includeOps = args.length >= 4 &&
            ("1".equals(args[3]) || "true".equalsIgnoreCase(args[3]));

        if (currentProgram == null) {
            printerr("[decompiler_cfg] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("include_ops", includeOps);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("resolution_error", "");
        envelope.put("block_count", 0);
        envelope.put("edge_count", 0);
        envelope.put("blocks", new ArrayList<Map<String, Object>>());
        envelope.put("edges", new ArrayList<Map<String, Object>>());
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("mermaid", "graph TD");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function root;
        try {
            root = resolveFunction(fm, nameOrAddress);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeEnvelope(outputPath, envelope);
            println("[decompiler_cfg] resolution failed for '" + nameOrAddress + "': " + re.getMessage());
            return;
        }

        envelope.put("resolved_address", root.getEntryPoint() != null ? root.getEntryPoint().toString() : "");
        envelope.put("resolved_function_name", safeFullName(root));

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.setSimplificationStyle(simplificationStyle);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);
        DecompileResults dr = decompiler.decompileFunction(root, 60, monitor);
        decompiler.dispose();

        if (dr == null) {
            envelope.put("decompile_error", "null result");
            writeEnvelope(outputPath, envelope);
            return;
        }

        envelope.put("decompile_completed", dr.decompileCompleted());
        envelope.put("decompile_valid", dr.isValid());
        envelope.put("is_timed_out", dr.isTimedOut());
        envelope.put("is_cancelled", dr.isCancelled());
        envelope.put("failed_to_start", dr.failedToStart());

        String errorMessage = dr.getErrorMessage();
        if (errorMessage != null && !errorMessage.isEmpty()) {
            envelope.put("decompile_error", errorMessage);
        }
        if (!dr.decompileCompleted()) {
            writeEnvelope(outputPath, envelope);
            return;
        }

        HighFunction hf = dr.getHighFunction();
        if (hf == null) {
            envelope.put("decompile_error", "HighFunction is null");
            writeEnvelope(outputPath, envelope);
            return;
        }

        ArrayList<PcodeBlockBasic> basicBlocks = hf.getBasicBlocks();
        List<Map<String, Object>> blocks = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();
        int capacity = (int) Math.ceil(basicBlocks.size() / 0.75f);
        HashMap<Integer, PcodeBlockBasic> byIndex = new HashMap<>(capacity);
        HashMap<Integer, LinkedHashSet<Integer>> predecessors = new HashMap<>(capacity);
        HashMap<Integer, LinkedHashSet<Integer>> successors = new HashMap<>(capacity);

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            byIndex.put(block.getIndex(), block);
            predecessors.put(block.getIndex(), new LinkedHashSet<Integer>());
            successors.put(block.getIndex(), new LinkedHashSet<Integer>());
        }

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            for (int i = 0; i < block.getOutSize(); i++) {
                PcodeBlock out = block.getOut(i);
                if (!(out instanceof PcodeBlockBasic)) {
                    continue;
                }
                PcodeBlockBasic dest = (PcodeBlockBasic) out;
                successors.get(block.getIndex()).add(dest.getIndex());
                predecessors.get(dest.getIndex()).add(block.getIndex());
            }
        }

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            Map<String, Object> blockMap = new LinkedHashMap<>();
            blockMap.put("index", block.getIndex());
            blockMap.put("start", block.getStart() != null ? block.getStart().toString() : "");
            blockMap.put("stop", block.getStop() != null ? block.getStop().toString() : "");
            blockMap.put("block_kind", blockKind(block, predecessors, successors, byIndex));
            blockMap.put("structural_tags", structuralTags(block, predecessors, successors, byIndex));
            BlockSummary summary = summarizeBlock(block, includeOps);
            blockMap.put("pcode_op_count", summary.count);
            blockMap.put("first_op_mnemonic", summary.firstMnemonic);
            blockMap.put("last_op_mnemonic", summary.lastMnemonic);
            blockMap.put("pcode_mnemonics_preview", summary.preview);
            blockMap.put("pcode_preview_truncated", summary.truncated);
            blockMap.put("defs_preview", summary.defsPreview);
            blockMap.put("defs_preview_truncated", summary.defsTruncated);
            blockMap.put("uses_preview", summary.usesPreview);
            blockMap.put("uses_preview_truncated", summary.usesTruncated);
            blockMap.put("instruction_addresses_preview", summary.addressesPreview);
            blockMap.put("instruction_addresses_truncated", summary.addressesTruncated);
            blockMap.put("call_count", summary.callCount);
            blockMap.put("callsites_preview", summary.callsitesPreview);
            blockMap.put("callsites_preview_truncated", summary.callsitesTruncated);
            blockMap.put("internal_call_count", summary.internalCallCount);
            blockMap.put("external_callsite_count", summary.externalCallsiteCount);
            blockMap.put("indirect_call_count", summary.indirectCallCount);
            blockMap.put("thunk_call_count", summary.thunkCallCount);
            blockMap.put("call_target_count", summary.callTargets.size());
            blockMap.put("call_targets", summary.callTargets);
            blockMap.put("call_targets_truncated", summary.callTargetsTruncated);
            blockMap.put("internal_call_target_count", summary.internalCallTargets.size());
            blockMap.put("internal_call_targets", summary.internalCallTargets);
            blockMap.put("internal_call_targets_truncated", summary.internalCallTargetsTruncated);
            blockMap.put("external_call_target_count", summary.externalCallTargets.size());
            blockMap.put("external_call_targets", summary.externalCallTargets);
            blockMap.put("external_call_targets_truncated", summary.externalCallTargetsTruncated);
            blockMap.put("memory_access_count", summary.memoryAccessCount);
            blockMap.put("memory_accesses_preview", summary.memoryAccessesPreview);
            blockMap.put("memory_accesses_preview_truncated", summary.memoryAccessesTruncated);
            blockMap.put("memory_read_count", summary.memoryReadCount);
            blockMap.put("memory_write_count", summary.memoryWriteCount);
            blockMap.put("constant_count", summary.constantCount);
            blockMap.put("constants_preview", summary.constantsPreview);
            blockMap.put("constants_preview_truncated", summary.constantsTruncated);
            blockMap.put("string_ref_count", summary.stringRefCount);
            blockMap.put("string_refs_preview", summary.stringRefsPreview);
            blockMap.put("string_refs_preview_truncated", summary.stringRefsTruncated);
            blockMap.put("external_ref_count", summary.externalRefCount);
            blockMap.put("external_refs_preview", summary.externalRefsPreview);
            blockMap.put("external_refs_preview_truncated", summary.externalRefsTruncated);
            blockMap.put("external_call_count", summary.externalCallCount);
            blockMap.put("external_address_ref_count", summary.externalAddressRefCount);
            blockMap.put("external_symbol_count", summary.externalSymbols.size());
            blockMap.put("external_symbols", summary.externalSymbols);
            blockMap.put("external_symbols_truncated", summary.externalSymbolsTruncated);
            blockMap.put("module_count", summary.modules.size());
            blockMap.put("modules", summary.modules);
            blockMap.put("api_family_count", summary.apiFamilies.size());
            blockMap.put("api_families", summary.apiFamilies);
            blockMap.put("api_tag_count", summary.apiTags.size());
            blockMap.put("api_tags", summary.apiTags);
            blockMap.put("predecessor_indices", toIntegerList(predecessors.get(block.getIndex())));
            blockMap.put("successor_indices", toIntegerList(successors.get(block.getIndex())));
            blockMap.put("ops", summary.ops);
            blockMap.put("incoming_edges", block.getInSize());
            blockMap.put("outgoing_edges", block.getOutSize());
            blocks.add(blockMap);
        }

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            for (int i = 0; i < block.getOutSize(); i++) {
                PcodeBlock out = block.getOut(i);
                if (!(out instanceof PcodeBlockBasic)) {
                    continue;
                }
                PcodeBlockBasic dest = (PcodeBlockBasic) out;
                Map<String, Object> edgeMap = new LinkedHashMap<>();
                edgeMap.put("from_index", block.getIndex());
                edgeMap.put("to_index", dest.getIndex());
                edgeMap.put("from", block.getStart() != null ? block.getStart().toString() : "");
                edgeMap.put("to", dest.getStart() != null ? dest.getStart().toString() : "");
                edgeMap.put("edge_index", i);
                edgeMap.put("label", edgeLabel(block, i));
                edgeMap.put("branch_kind", branchKind(block, i));
                edgeMap.put("source_op_mnemonic", lastOpMnemonic(block));
                edgeMap.put("source_op_address", lastOpAddress(block));
                edgeMap.put("branch_target_preview", branchTargetPreview(block));
                edgeMap.put("condition_preview", conditionPreview(block));
                edgeMap.put("predicate_mnemonic", predicateMnemonic(block));
                edgeMap.put("predicate_inputs_preview", predicateInputsPreview(block));
                edges.add(edgeMap);
            }
        }

        envelope.put("block_count", blocks.size());
        envelope.put("edge_count", edges.size());
        envelope.put("blocks", blocks);
        envelope.put("edges", edges);
        envelope.put("mermaid", renderMermaid(basicBlocks, edges));

        writeEnvelope(outputPath, envelope);
        println("[decompiler_cfg] rooted at " + safeFullName(root) + "; blocks=" + blocks.size()
            + ", edges=" + edges.size() + " -> " + outputPath);
    }

    private BlockSummary summarizeBlock(PcodeBlockBasic block, boolean includeOps) {
        int count = 0;
        String firstMnemonic = "";
        String lastMnemonic = "";
        boolean truncated = false;
        List<String> preview = new ArrayList<>();
        LinkedHashSet<String> defs = new LinkedHashSet<>();
        LinkedHashSet<String> uses = new LinkedHashSet<>();
        LinkedHashSet<String> addresses = new LinkedHashSet<>();
        LinkedHashSet<String> callTargets = new LinkedHashSet<>();
        LinkedHashSet<String> internalCallTargets = new LinkedHashSet<>();
        LinkedHashSet<String> externalCallTargets = new LinkedHashSet<>();
        List<Map<String, Object>> callsites = new ArrayList<>();
        boolean callsitesTruncated = false;
        int callCount = 0;
        int internalCallCount = 0;
        int externalCallsiteCount = 0;
        int indirectCallCount = 0;
        int thunkCallCount = 0;
        List<Map<String, Object>> memoryAccesses = new ArrayList<>();
        boolean memoryAccessesTruncated = false;
        int memoryAccessCount = 0;
        int memoryReadCount = 0;
        int memoryWriteCount = 0;
        LinkedHashMap<String, Map<String, Object>> constants = new LinkedHashMap<>();
        LinkedHashMap<String, Map<String, Object>> stringRefs = new LinkedHashMap<>();
        LinkedHashMap<String, Map<String, Object>> externalRefs = new LinkedHashMap<>();
        LinkedHashSet<String> externalSymbols = new LinkedHashSet<>();
        LinkedHashSet<String> modules = new LinkedHashSet<>();
        LinkedHashSet<String> apiFamilies = new LinkedHashSet<>();
        LinkedHashSet<String> apiTags = new LinkedHashSet<>();
        int externalCallCount = 0;
        int externalAddressRefCount = 0;
        List<Map<String, Object>> ops = new ArrayList<>();
        Iterator<PcodeOp> it = block.getIterator();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            if (op != null) {
                count++;
                String mnemonic = safeMnemonic(op);
                if (firstMnemonic.isEmpty()) {
                    firstMnemonic = mnemonic;
                }
                lastMnemonic = mnemonic;
                if (preview.size() < MNEMONIC_PREVIEW_LIMIT) {
                    preview.add(mnemonic);
                } else {
                    truncated = true;
                }
                Varnode out = op.getOutput();
                if (out != null) {
                    defs.add(formatVarnode(out));
                }
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode in = op.getInput(i);
                    if (in != null) {
                        uses.add(formatVarnode(in));
                        if (in.isConstant()) {
                            String key = constantKey(in);
                            if (!constants.containsKey(key)) {
                                constants.put(key, formatConstant(in, mnemonic));
                            }
                        }
                        captureStringRef(stringRefs, in, mnemonic);
                    }
                }
                if (out != null) {
                    captureStringRef(stringRefs, out, mnemonic);
                }
                captureExternalRefs(externalRefs, op, mnemonic);
                externalCallCount = countExternalRefsByKind(externalRefs, "call_target");
                externalAddressRefCount = countExternalRefsByKind(externalRefs, "address_ref");
                captureExternalSymbols(externalSymbols, externalRefs);
                captureModules(modules, externalRefs);
                captureApiFamilies(apiFamilies, externalRefs);
                captureApiTags(apiTags, externalRefs);
                if (includeOps) {
                    ops.add(formatOp(op));
                }
                String opAddress = opAddress(op);
                if (!opAddress.isEmpty()) {
                    addresses.add(opAddress);
                }
                if (isCallOp(op)) {
                    callCount++;
                    Map<String, Object> callsite = formatCallsite(block, op);
                    if (Boolean.TRUE.equals(callsite.get("is_external"))) {
                        externalCallsiteCount++;
                        captureTypedCallTarget(externalCallTargets, callsite);
                    } else {
                        internalCallCount++;
                        captureTypedCallTarget(internalCallTargets, callsite);
                    }
                    if (Boolean.TRUE.equals(callsite.get("is_indirect"))) {
                        indirectCallCount++;
                    }
                    if (Boolean.TRUE.equals(callsite.get("is_thunk"))) {
                        thunkCallCount++;
                    }
                    captureTypedCallTarget(callTargets, callsite);
                    if (callsites.size() < VARNODE_PREVIEW_LIMIT) {
                        callsites.add(callsite);
                    } else {
                        callsitesTruncated = true;
                    }
                }
                List<Map<String, Object>> opMemoryAccesses = formatMemoryAccesses(op);
                for (Map<String, Object> access : opMemoryAccesses) {
                    memoryAccessCount++;
                    if ("write".equals(access.get("access_kind"))) {
                        memoryWriteCount++;
                    } else {
                        memoryReadCount++;
                    }
                    if (memoryAccesses.size() < VARNODE_PREVIEW_LIMIT) {
                        memoryAccesses.add(access);
                    } else {
                        memoryAccessesTruncated = true;
                    }
                }
            }
        }
        return new BlockSummary(
            count,
            firstMnemonic,
            lastMnemonic,
            preview,
            truncated,
            truncatePreview(defs),
            defs.size() > VARNODE_PREVIEW_LIMIT,
            truncatePreview(uses),
            uses.size() > VARNODE_PREVIEW_LIMIT,
            truncateAddressPreview(addresses),
            addresses.size() > ADDRESS_PREVIEW_LIMIT,
            callCount,
            callsites,
            callsitesTruncated,
            internalCallCount,
            externalCallsiteCount,
            indirectCallCount,
            thunkCallCount,
            truncatePreview(callTargets),
            callTargets.size() > VARNODE_PREVIEW_LIMIT,
            truncatePreview(internalCallTargets),
            internalCallTargets.size() > VARNODE_PREVIEW_LIMIT,
            truncatePreview(externalCallTargets),
            externalCallTargets.size() > VARNODE_PREVIEW_LIMIT,
            memoryAccessCount,
            memoryAccesses,
            memoryAccessesTruncated,
            memoryReadCount,
            memoryWriteCount,
            constants.size(),
            truncateConstantPreview(constants),
            constants.size() > VARNODE_PREVIEW_LIMIT,
            stringRefs.size(),
            truncateStringRefPreview(stringRefs),
            stringRefs.size() > VARNODE_PREVIEW_LIMIT,
            externalRefs.size(),
            truncateExternalRefPreview(externalRefs),
            externalRefs.size() > VARNODE_PREVIEW_LIMIT,
            externalCallCount,
            externalAddressRefCount,
            truncatePreview(externalSymbols),
            externalSymbols.size() > VARNODE_PREVIEW_LIMIT,
            new ArrayList<String>(modules),
            new ArrayList<String>(apiFamilies),
            new ArrayList<String>(apiTags),
            ops
        );
    }

    private List<String> truncateAddressPreview(LinkedHashSet<String> items) {
        List<String> out = new ArrayList<>();
        int count = 0;
        for (String item : items) {
            if (count >= ADDRESS_PREVIEW_LIMIT) {
                break;
            }
            out.add(item);
            count++;
        }
        return out;
    }

    private List<Integer> toIntegerList(LinkedHashSet<Integer> items) {
        List<Integer> out = new ArrayList<>();
        if (items == null) {
            return out;
        }
        out.addAll(items);
        return out;
    }

    private Map<String, Object> formatOp(PcodeOp op) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("seq_num", op.getSeqnum() != null && op.getSeqnum().getTarget() != null
            ? op.getSeqnum().getTarget().toString() + "@" + op.getSeqnum().getTime()
            : "");
        out.put("mnemonic", safeMnemonic(op));
        out.put("output", op.getOutput() != null ? formatVarnode(op.getOutput()) : "");
        List<String> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode in = op.getInput(i);
            if (in != null) {
                inputs.add(formatVarnode(in));
            }
        }
        out.put("inputs", inputs);
        return out;
    }

    private boolean isCallOp(PcodeOp op) {
        if (op == null) {
            return false;
        }
        switch (op.getOpcode()) {
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
                return true;
            default:
                return false;
        }
    }

    private void captureTypedCallTarget(LinkedHashSet<String> callTargets, Map<String, Object> callsite) {
        if (callTargets == null || callsite == null) {
            return;
        }
        Object targetName = callsite.get("target_name");
        if (targetName instanceof String) {
            String name = ((String) targetName).trim();
            if (!name.isEmpty()) {
                callTargets.add(name);
            }
        }
    }

    private Map<String, Object> formatCallsite(PcodeBlockBasic block, PcodeOp op) {
        Map<String, Object> out = new LinkedHashMap<>();
        Function target = resolveCallTarget(op);
        boolean isIndirect = op != null && op.getOpcode() == PcodeOp.CALLIND;
        String fullName = target != null ? safeFullName(target) : "";
        String moduleName = normalizeModuleName(externalModuleName(fullName));
        CallContext callContext = callContextPreview(block, op);
        out.put("mnemonic", safeMnemonic(op));
        out.put("op_address", opAddress(op));
        out.put("target_name", fullName);
        out.put("target_address", target != null && target.getEntryPoint() != null
            ? target.getEntryPoint().toString() : "");
        out.put("target_preview", callTargetPreview(op));
        out.put("call_context_preview", callContext.preview);
        out.put("call_context_truncated", callContext.truncated);
        out.put("module_name", target != null && target.isExternal() ? moduleName : "");
        out.put("api_family", target != null && target.isExternal() ? classifyApiFamily(moduleName) : "");
        out.put("api_tag", target != null && target.isExternal()
            ? classifyApiTag(fullName, moduleName) : "");
        out.put("is_external", target != null && target.isExternal());
        out.put("is_thunk", target != null && target.isThunk());
        out.put("is_indirect", isIndirect);
        return out;
    }

    private CallContext callContextPreview(PcodeBlockBasic block, PcodeOp op) {
        List<String> preview = new ArrayList<>();
        if (block == null || op == null) {
            return new CallContext(preview, false);
        }
        String addr = opAddress(op);
        if (addr.isEmpty()) {
            return new CallContext(preview, false);
        }
        try {
            Address opAddr = currentProgram.getAddressFactory().getAddress(addr);
            if (opAddr == null) {
                return new CallContext(preview, false);
            }
            Address blockStart = block.getStart();
            Instruction instr = getInstructionAt(opAddr);
            boolean truncated = false;
            while (instr != null) {
                Address instrAddr = instr.getAddress();
                if (blockStart != null && instrAddr.compareTo(blockStart) < 0) {
                    break;
                }
                preview.add(0, formatInstruction(instr));
                if (preview.size() >= CALL_CONTEXT_PREVIEW_LIMIT) {
                    Instruction previous = currentProgram.getListing().getInstructionBefore(instrAddr);
                    truncated = previous != null && (blockStart == null ||
                        previous.getAddress().compareTo(blockStart) >= 0);
                    break;
                }
                instr = currentProgram.getListing().getInstructionBefore(instrAddr);
            }
            return new CallContext(preview, truncated);
        } catch (Exception e) {
            return new CallContext(preview, false);
        }
    }

    private String formatInstruction(Instruction instr) {
        if (instr == null) {
            return "";
        }
        String address = instr.getAddress() != null ? instr.getAddress().toString() : "";
        return address + " " + instr.toString();
    }

    private List<Map<String, Object>> formatMemoryAccesses(PcodeOp op) {
        List<Map<String, Object>> accesses = new ArrayList<>();
        if (op == null) {
            return accesses;
        }
        if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
            accesses.add(formatLoadStoreMemoryAccess(op));
            return accesses;
        }

        Varnode out = op.getOutput();
        if (isDirectMemoryVarnode(out)) {
            accesses.add(formatDirectMemoryAccess("write", op, out, firstInputPreview(op)));
        }
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode in = op.getInput(i);
            if (isDirectMemoryVarnode(in)) {
                accesses.add(formatDirectMemoryAccess("read", op, in, formatVarnode(in)));
            }
        }
        return accesses;
    }

    private Map<String, Object> formatLoadStoreMemoryAccess(PcodeOp op) {
        Map<String, Object> out = new LinkedHashMap<>();
        boolean isStore = op != null && op.getOpcode() == PcodeOp.STORE;
        Varnode addressNode = op != null && op.getNumInputs() >= 2 ? op.getInput(1) : null;
        Varnode valueNode = null;
        if (op != null) {
            if (isStore && op.getNumInputs() >= 3) {
                valueNode = op.getInput(2);
            } else if (!isStore) {
                valueNode = op.getOutput();
            }
        }
        out.put("access_kind", isStore ? "write" : "read");
        out.put("op_address", opAddress(op));
        out.put("address_preview", addressNode != null ? formatVarnode(addressNode) : "");
        out.put("value_preview", valueNode != null ? formatVarnode(valueNode) : "");
        out.put("space_kind", memorySpaceKind(addressNode));
        return out;
    }

    private Map<String, Object> formatDirectMemoryAccess(
        String accessKind,
        PcodeOp op,
        Varnode addressNode,
        String valuePreview
    ) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_kind", accessKind);
        out.put("op_address", opAddress(op));
        out.put("address_preview", addressNode != null ? formatVarnode(addressNode) : "");
        out.put("value_preview", valuePreview != null ? valuePreview : "");
        out.put("space_kind", memorySpaceKind(addressNode));
        return out;
    }

    private boolean isDirectMemoryVarnode(Varnode vn) {
        if (vn == null || vn.isConstant() || vn.isRegister() || vn.isUnique()) {
            return false;
        }
        try {
            return vn.isAddress() && vn.getAddress() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private String firstInputPreview(PcodeOp op) {
        if (op == null || op.getNumInputs() == 0 || op.getInput(0) == null) {
            return "";
        }
        return formatVarnode(op.getInput(0));
    }

    private String constantKey(Varnode vn) {
        if (vn == null) {
            return "";
        }
        return Long.toUnsignedString(vn.getOffset()) + ":" + vn.getSize();
    }

    private Map<String, Object> formatConstant(Varnode vn, String sourceOpMnemonic) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("value_hex", "0x" + Long.toHexString(vn.getOffset()));
        out.put("size_bytes", vn.getSize());
        out.put("source_op_mnemonic", sourceOpMnemonic != null ? sourceOpMnemonic : "");
        return out;
    }

    private List<Map<String, Object>> truncateConstantPreview(LinkedHashMap<String, Map<String, Object>> items) {
        List<Map<String, Object>> out = new ArrayList<>();
        int count = 0;
        for (Map<String, Object> item : items.values()) {
            if (count >= VARNODE_PREVIEW_LIMIT) {
                break;
            }
            out.add(item);
            count++;
        }
        return out;
    }

    private void captureStringRef(LinkedHashMap<String, Map<String, Object>> stringRefs, Varnode vn, String sourceOpMnemonic) {
        Map<String, Object> ref = formatStringRef(vn, sourceOpMnemonic);
        if (ref == null) {
            return;
        }
        String key = (String) ref.get("address");
        if (!stringRefs.containsKey(key)) {
            stringRefs.put(key, ref);
        }
    }

    private Map<String, Object> formatStringRef(Varnode vn, String sourceOpMnemonic) {
        if (vn == null || !vn.isAddress() || vn.getAddress() == null) {
            return null;
        }
        try {
            Data data = currentProgram.getListing().getDefinedDataContaining(vn.getAddress());
            if (data == null || !data.hasStringValue()) {
                return null;
            }
            Object valueObj = data.getValue();
            if (!(valueObj instanceof String)) {
                return null;
            }
            String value = (String) valueObj;
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("value", value);
            out.put("address", data.getAddress() != null ? data.getAddress().toString() : "");
            out.put("source_op_mnemonic", sourceOpMnemonic != null ? sourceOpMnemonic : "");
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private List<Map<String, Object>> truncateStringRefPreview(LinkedHashMap<String, Map<String, Object>> items) {
        List<Map<String, Object>> out = new ArrayList<>();
        int count = 0;
        for (Map<String, Object> item : items.values()) {
            if (count >= VARNODE_PREVIEW_LIMIT) {
                break;
            }
            out.add(item);
            count++;
        }
        return out;
    }

    private void captureExternalRefs(LinkedHashMap<String, Map<String, Object>> externalRefs, PcodeOp op, String sourceOpMnemonic) {
        if (op == null) {
            return;
        }
        Function target = resolveCallTarget(op);
        if (target != null && target.isExternal()) {
            Map<String, Object> ref = new LinkedHashMap<>();
            String fullName = safeFullName(target);
            String moduleName = normalizeModuleName(externalModuleName(fullName));
            ref.put("name", fullName);
            ref.put("module_name", moduleName);
            ref.put("api_family", classifyApiFamily(moduleName));
            ref.put("api_tag", classifyApiTag(fullName, moduleName));
            ref.put("address", target.getEntryPoint() != null ? target.getEntryPoint().toString() : "");
            ref.put("ref_kind", "call_target");
            ref.put("source_op_mnemonic", sourceOpMnemonic != null ? sourceOpMnemonic : "");
            ref.put("source_op_address", opAddress(op));
            ref.put("source_value_preview", callTargetPreview(op));
            String key = "call:" + ref.get("name") + "@" + ref.get("address");
            if (!externalRefs.containsKey(key)) {
                externalRefs.put(key, ref);
            }
        }

        for (int i = 0; i < op.getNumInputs(); i++) {
            captureExternalAddressRef(externalRefs, op.getInput(i), sourceOpMnemonic, opAddress(op));
        }
        captureExternalAddressRef(externalRefs, op.getOutput(), sourceOpMnemonic, opAddress(op));
    }

    private void captureExternalAddressRef(
        LinkedHashMap<String, Map<String, Object>> externalRefs,
        Varnode vn,
        String sourceOpMnemonic,
        String sourceOpAddress
    ) {
        Map<String, Object> ref = formatExternalAddressRef(vn, sourceOpMnemonic, sourceOpAddress);
        if (ref == null) {
            return;
        }
        String key = "addr:" + ref.get("name") + "@" + ref.get("address");
        if (!externalRefs.containsKey(key)) {
            externalRefs.put(key, ref);
        }
    }

    private Map<String, Object> formatExternalAddressRef(
        Varnode vn,
        String sourceOpMnemonic,
        String sourceOpAddress
    ) {
        if (vn == null || !vn.isAddress() || vn.getAddress() == null) {
            return null;
        }
        try {
            Symbol symbol = getSymbolAt(vn.getAddress());
            if (symbol == null || symbol.getParentNamespace() == null || !symbol.getParentNamespace().isExternal()) {
                return null;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            String fullName = symbol.getName(true);
            String moduleName = normalizeModuleName(externalModuleName(fullName));
            out.put("name", fullName);
            out.put("module_name", moduleName);
            out.put("api_family", classifyApiFamily(moduleName));
            out.put("api_tag", classifyApiTag(fullName, moduleName));
            out.put("address", vn.getAddress().toString());
            out.put("ref_kind", "address_ref");
            out.put("source_op_mnemonic", sourceOpMnemonic != null ? sourceOpMnemonic : "");
            out.put("source_op_address", sourceOpAddress != null ? sourceOpAddress : "");
            out.put("source_value_preview", formatVarnode(vn));
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private List<Map<String, Object>> truncateExternalRefPreview(LinkedHashMap<String, Map<String, Object>> items) {
        List<Map<String, Object>> out = new ArrayList<>();
        int count = 0;
        for (Map<String, Object> item : items.values()) {
            if (count >= VARNODE_PREVIEW_LIMIT) {
                break;
            }
            out.add(item);
            count++;
        }
        return out;
    }

    private String externalModuleName(String fullName) {
        if (fullName == null || fullName.isEmpty()) {
            return "";
        }
        int idx = fullName.indexOf("::");
        if (idx <= 0) {
            return fullName;
        }
        return fullName.substring(0, idx);
    }

    private String normalizeModuleName(String moduleName) {
        if (moduleName == null) {
            return "";
        }
        return moduleName.trim().toLowerCase();
    }

    private void captureApiFamilies(
        LinkedHashSet<String> apiFamilies,
        LinkedHashMap<String, Map<String, Object>> externalRefs
    ) {
        apiFamilies.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object moduleObj = ref.get("module_name");
            if (!(moduleObj instanceof String)) {
                continue;
            }
            String family = classifyApiFamily((String) moduleObj);
            if (!family.isEmpty()) {
                apiFamilies.add(family);
            }
        }
    }

    private void captureModules(
        LinkedHashSet<String> modules,
        LinkedHashMap<String, Map<String, Object>> externalRefs
    ) {
        modules.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object moduleObj = ref.get("module_name");
            if (!(moduleObj instanceof String)) {
                continue;
            }
            String moduleName = ((String) moduleObj).trim();
            if (!moduleName.isEmpty()) {
                modules.add(moduleName);
            }
        }
    }

    private void captureExternalSymbols(
        LinkedHashSet<String> externalSymbols,
        LinkedHashMap<String, Map<String, Object>> externalRefs
    ) {
        externalSymbols.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object nameObj = ref.get("name");
            if (!(nameObj instanceof String)) {
                continue;
            }
            String name = ((String) nameObj).trim();
            if (!name.isEmpty()) {
                externalSymbols.add(name);
            }
        }
    }

    private int countExternalRefsByKind(
        LinkedHashMap<String, Map<String, Object>> externalRefs,
        String refKind
    ) {
        int count = 0;
        for (Map<String, Object> ref : externalRefs.values()) {
            Object kindObj = ref.get("ref_kind");
            if (kindObj instanceof String && refKind.equals(kindObj)) {
                count++;
            }
        }
        return count;
    }

    private String classifyApiFamily(String moduleName) {
        if (moduleName == null) {
            return "";
        }
        String mod = moduleName.trim().toLowerCase();
        if (mod.isEmpty()) {
            return "";
        }
        if (mod.equals("kernel32.dll") || mod.equals("ntdll.dll")) {
            return "process";
        }
        if (mod.equals("advapi32.dll")) {
            return "registry";
        }
        if (mod.equals("ws2_32.dll") || mod.equals("wininet.dll") || mod.equals("winhttp.dll") ||
            mod.equals("urlmon.dll")) {
            return "network";
        }
        if (mod.equals("user32.dll") || mod.equals("gdi32.dll") || mod.equals("comctl32.dll")) {
            return "ui";
        }
        if (mod.equals("shell32.dll") || mod.equals("shlwapi.dll")) {
            return "shell";
        }
        if (mod.equals("ole32.dll") || mod.equals("oleaut32.dll") || mod.equals("combase.dll")) {
            return "com";
        }
        if (mod.equals("bcrypt.dll") || mod.equals("crypt32.dll") || mod.equals("ncrypt.dll")) {
            return "crypto";
        }
        if (mod.equals("kernelbase.dll")) {
            return "system";
        }
        return "";
    }

    private void captureApiTags(
        LinkedHashSet<String> apiTags,
        LinkedHashMap<String, Map<String, Object>> externalRefs
    ) {
        apiTags.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object nameObj = ref.get("name");
            Object moduleObj = ref.get("module_name");
            String tag = classifyApiTag(
                nameObj instanceof String ? (String) nameObj : "",
                moduleObj instanceof String ? (String) moduleObj : ""
            );
            if (!tag.isEmpty()) {
                apiTags.add(tag);
            }
        }
    }

    private String classifyApiTag(String fullName, String moduleName) {
        String mod = moduleName != null ? moduleName.trim().toLowerCase() : "";
        String func = externalFunctionName(fullName).toLowerCase();
        if (func.isEmpty()) {
            return "";
        }

        if (func.contains("createfile") || func.contains("readfile") || func.contains("writefile") ||
            func.contains("setfile") || func.contains("findfirstfile") || func.contains("findnextfile") ||
            func.contains("getfile") || func.contains("movefile") || func.contains("deletefile") ||
            func.contains("copyfile")) {
            return "file";
        }
        if (func.contains("createthread") || func.contains("openprocess") || func.contains("terminateprocess") ||
            func.contains("resumethread") || func.contains("suspendthread") || func.contains("process")) {
            return "process";
        }
        if (func.contains("virtualalloc") || func.contains("virtualprotect") || func.contains("heap") ||
            func.contains("alloc") || func.contains("free")) {
            return "memory";
        }
        if (func.contains("tickcount") || func.contains("queryperformance") || func.contains("systemtime") ||
            func.contains("filetime") || func.contains("sleep") || func.contains("time")) {
            return "timing";
        }
        if (func.contains("regopen") || func.contains("regset") || func.contains("regquery") ||
            func.contains("regcreate") || func.contains("regdelete")) {
            return "registry";
        }
        if (func.contains("socket") || func.contains("connect") || func.contains("send") ||
            func.contains("recv") || func.contains("http") || func.contains("internet")) {
            return "network";
        }
        if (func.contains("window") || func.contains("message") || func.contains("dialog") ||
            func.contains("cursor") || func.contains("draw") || func.contains("paint") ||
            func.contains("text") || func.contains("icon")) {
            return "ui";
        }
        if (func.contains("crypt") || func.contains("bcrypt") || func.contains("hash") ||
            func.contains("encrypt") || func.contains("decrypt")) {
            return "crypto";
        }

        if (mod.equals("advapi32.dll")) {
            return "registry";
        }
        if (mod.equals("ws2_32.dll") || mod.equals("wininet.dll") || mod.equals("winhttp.dll") ||
            mod.equals("urlmon.dll")) {
            return "network";
        }
        if (mod.equals("user32.dll") || mod.equals("gdi32.dll") || mod.equals("comctl32.dll")) {
            return "ui";
        }
        return "";
    }

    private String externalFunctionName(String fullName) {
        if (fullName == null || fullName.isEmpty()) {
            return "";
        }
        int idx = fullName.indexOf("::");
        if (idx < 0 || idx + 2 >= fullName.length()) {
            return fullName;
        }
        return fullName.substring(idx + 2);
    }

    private String memorySpaceKind(Varnode addressNode) {
        if (addressNode == null) {
            return "unknown";
        }
        try {
            HighVariable high = addressNode.getHigh();
            if (high != null && high.getName() != null) {
                String name = high.getName().toLowerCase();
                if (name.contains("stack") || name.contains("local_")) {
                    return "stack";
                }
            }
        } catch (Exception e) {
        }
        try {
            if (addressNode.getAddress() != null &&
                addressNode.getAddress().getAddressSpace() != null) {
                String spaceName = addressNode.getAddress().getAddressSpace().getName();
                if (spaceName != null) {
                    String lower = spaceName.toLowerCase();
                    if (lower.contains("stack")) {
                        return "stack";
                    }
                    if (lower.contains("ram") || lower.contains("mem")) {
                        return "global";
                    }
                }
            }
            if (addressNode.isConstant()) {
                return "constant_address";
            }
            if (addressNode.isAddress()) {
                return "global";
            }
            if (addressNode.isRegister()) {
                return "register_derived";
            }
            if (addressNode.isUnique()) {
                return "temporary";
            }
        } catch (Exception e) {
        }
        return "unknown";
    }

    private String callTargetPreview(PcodeOp op) {
        if (op == null || op.getNumInputs() < 1) {
            return "";
        }
        Varnode target = op.getInput(0);
        return target != null ? formatVarnode(target) : "";
    }

    private Function resolveCallTarget(PcodeOp op) {
        if (op == null || op.getNumInputs() < 1) {
            return null;
        }
        try {
            Varnode target = op.getInput(0);
            if (target != null && target.getAddress() != null) {
                Function fn = currentProgram.getFunctionManager().getFunctionAt(target.getAddress());
                if (fn != null) {
                    return fn;
                }
                fn = currentProgram.getFunctionManager().getFunctionContaining(target.getAddress());
                if (fn != null) {
                    return fn;
                }
            }
        } catch (Exception e) {
        }
        try {
            String addr = opAddress(op);
            if (!addr.isEmpty()) {
                Instruction instr = getInstructionAt(currentProgram.getAddressFactory().getAddress(addr));
                if (instr != null) {
                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address flow : flows) {
                            if (flow == null) {
                                continue;
                            }
                            Function fn = currentProgram.getFunctionManager().getFunctionAt(flow);
                            if (fn != null) {
                                return fn;
                            }
                            fn = currentProgram.getFunctionManager().getFunctionContaining(flow);
                            if (fn != null) {
                                return fn;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    private List<String> truncatePreview(LinkedHashSet<String> items) {
        List<String> out = new ArrayList<>();
        int count = 0;
        for (String item : items) {
            if (count >= VARNODE_PREVIEW_LIMIT) {
                break;
            }
            out.add(item);
            count++;
        }
        return out;
    }

    private String safeMnemonic(PcodeOp op) {
        try {
            String mnemonic = op.getMnemonic();
            return mnemonic != null ? mnemonic : "";
        } catch (Exception e) {
            return "";
        }
    }

    private String formatVarnode(Varnode vn) {
        if (vn == null) {
            return "";
        }
        String storage;
        try {
            storage = vn.encodePiece();
        } catch (Exception e) {
            storage = "";
        }
        String name = "";
        try {
            HighVariable high = vn.getHigh();
            if (high != null && high.getName() != null) {
                name = high.getName();
            }
        } catch (Exception e) {
            name = "";
        }
        if (name.isEmpty()) {
            if (vn.isRegister()) {
                name = "register";
            } else if (vn.isUnique()) {
                name = "unique";
            } else if (vn.isConstant()) {
                name = "const";
            } else if (vn.isAddress()) {
                name = "mem";
            } else {
                name = "varnode";
            }
        }
        return name + "<" + storage + ">";
    }

    private String edgeLabel(PcodeBlockBasic block, int outIndex) {
        if (block.getOutSize() == 2) {
            return outIndex == 0 ? "false" : "true";
        }
        return "edge_" + outIndex;
    }

    private String blockKind(
        PcodeBlockBasic block,
        HashMap<Integer, LinkedHashSet<Integer>> predecessors,
        HashMap<Integer, LinkedHashSet<Integer>> successors,
        HashMap<Integer, PcodeBlockBasic> byIndex
    ) {
        LinkedHashSet<String> tags = structuralTagsSet(block, predecessors, successors, byIndex);
        if (tags.contains("entry")) {
            return "entry";
        }
        if (tags.contains("exit")) {
            return "exit";
        }
        if (tags.contains("switch_like")) {
            return "switch";
        }
        if (tags.contains("conditional")) {
            return "conditional";
        }
        if (tags.contains("loop_latch")) {
            return "loop_latch";
        }
        if (tags.contains("loop_header")) {
            return "loop_header";
        }
        if (tags.contains("merge")) {
            return "merge";
        }
        if (tags.contains("branch")) {
            return "branch";
        }
        return "linear";
    }

    private List<String> structuralTags(
        PcodeBlockBasic block,
        HashMap<Integer, LinkedHashSet<Integer>> predecessors,
        HashMap<Integer, LinkedHashSet<Integer>> successors,
        HashMap<Integer, PcodeBlockBasic> byIndex
    ) {
        return new ArrayList<>(structuralTagsSet(block, predecessors, successors, byIndex));
    }

    private LinkedHashSet<String> structuralTagsSet(
        PcodeBlockBasic block,
        HashMap<Integer, LinkedHashSet<Integer>> predecessors,
        HashMap<Integer, LinkedHashSet<Integer>> successors,
        HashMap<Integer, PcodeBlockBasic> byIndex
    ) {
        LinkedHashSet<String> tags = new LinkedHashSet<>();
        LinkedHashSet<Integer> predIndices = predecessors.get(block.getIndex());
        LinkedHashSet<Integer> succIndices = successors.get(block.getIndex());
        int predCount = predIndices != null ? predIndices.size() : 0;
        int succCount = succIndices != null ? succIndices.size() : 0;

        if (predCount == 0) {
            tags.add("entry");
        }
        if (succCount == 0 || branchKind(block, 0).equals("return")) {
            tags.add("exit");
        }
        if (predCount > 1) {
            tags.add("merge");
        }
        if (succCount > 1) {
            tags.add("branch");
        }

        PcodeOp lastOp = block.getLastOp();
        int opcode = lastOp != null ? lastOp.getOpcode() : -1;
        if (opcode == PcodeOp.CBRANCH && succCount == 2) {
            tags.add("conditional");
        }
        if ((opcode == PcodeOp.BRANCHIND && succCount > 1) || succCount > 2) {
            tags.add("switch_like");
        }

        if (predIndices != null) {
            for (Integer predIndex : predIndices) {
                PcodeBlockBasic pred = byIndex.get(predIndex);
                if (pred != null && isBackEdge(pred, block)) {
                    tags.add("loop_header");
                    break;
                }
            }
        }

        if (succIndices != null) {
            for (Integer succIndex : succIndices) {
                PcodeBlockBasic succ = byIndex.get(succIndex);
                if (succ != null && isBackEdge(block, succ)) {
                    tags.add("loop_latch");
                    break;
                }
            }
        }

        if (succIndices != null && succIndices.contains(block.getIndex())) {
            tags.add("self_loop");
        }

        return tags;
    }

    private boolean isBackEdge(PcodeBlockBasic from, PcodeBlockBasic to) {
        if (from == null || to == null || from.getStart() == null || to.getStart() == null) {
            return false;
        }
        try {
            return from.getStart().compareTo(to.getStart()) >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    private String branchKind(PcodeBlockBasic block, int outIndex) {
        PcodeOp op = block.getLastOp();
        if (op == null) {
            return "unknown";
        }
        switch (op.getOpcode()) {
            case PcodeOp.CBRANCH:
                return outIndex == 0 ? "conditional_false" : "conditional_true";
            case PcodeOp.BRANCH:
                return "jump";
            case PcodeOp.BRANCHIND:
                return "indirect_jump";
            case PcodeOp.RETURN:
                return "return";
            case PcodeOp.CALL:
                return "call";
            case PcodeOp.CALLIND:
                return "indirect_call";
            default:
                return "flow";
        }
    }

    private String lastOpMnemonic(PcodeBlockBasic block) {
        PcodeOp op = block.getLastOp();
        return op != null ? safeMnemonic(op) : "";
    }

    private String lastOpAddress(PcodeBlockBasic block) {
        PcodeOp op = block.getLastOp();
        return opAddress(op);
    }

    private String branchTargetPreview(PcodeBlockBasic block) {
        PcodeOp op = block.getLastOp();
        if (op == null || op.getNumInputs() < 1) {
            return "";
        }
        switch (op.getOpcode()) {
            case PcodeOp.CBRANCH:
            case PcodeOp.BRANCH:
            case PcodeOp.BRANCHIND:
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
                return formatVarnode(op.getInput(0));
            default:
                return "";
        }
    }

    private String conditionPreview(PcodeBlockBasic block) {
        PcodeOp op = block.getLastOp();
        if (op == null || op.getOpcode() != PcodeOp.CBRANCH || op.getNumInputs() < 2) {
            return "";
        }
        return formatVarnode(op.getInput(1));
    }

    private String predicateMnemonic(PcodeBlockBasic block) {
        PcodeOp predicate = predicateOp(block);
        return predicate != null ? safeMnemonic(predicate) : "";
    }

    private List<String> predicateInputsPreview(PcodeBlockBasic block) {
        List<String> out = new ArrayList<>();
        PcodeOp predicate = predicateOp(block);
        if (predicate == null) {
            return out;
        }
        for (int i = 0; i < predicate.getNumInputs(); i++) {
            Varnode in = predicate.getInput(i);
            if (in != null) {
                out.add(formatVarnode(in));
            }
        }
        return out;
    }

    private PcodeOp predicateOp(PcodeBlockBasic block) {
        PcodeOp branch = block != null ? block.getLastOp() : null;
        if (branch == null || branch.getOpcode() != PcodeOp.CBRANCH || branch.getNumInputs() < 2) {
            return null;
        }
        Varnode condition = branch.getInput(1);
        if (condition == null) {
            return null;
        }
        try {
            return condition.getDef();
        } catch (Exception e) {
            return null;
        }
    }

    private String opAddress(PcodeOp op) {
        if (op == null || op.getSeqnum() == null || op.getSeqnum().getTarget() == null) {
            return "";
        }
        return op.getSeqnum().getTarget().toString();
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
            Function hit = fm.getFunctionContaining(targetAddress);
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

    private String renderMermaid(List<PcodeBlockBasic> blocks, List<Map<String, Object>> edges) {
        if (blocks.isEmpty()) {
            return "graph TD";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("graph TD\n");
        for (PcodeBlockBasic block : blocks) {
            if (block == null) {
                continue;
            }
            sb.append("  b").append(block.getIndex()).append("[\"")
                .append(escapeMermaid(block.getIndex() + ": " +
                    (block.getStart() != null ? block.getStart().toString() : "")))
                .append("\"]\n");
        }
        for (Map<String, Object> edge : edges) {
            sb.append("  b").append(edge.get("from_index"))
                .append(" -->|").append(escapeMermaid(String.valueOf(edge.get("label"))))
                .append("| b").append(edge.get("to_index")).append("\n");
        }
        return sb.toString();
    }

    private String escapeMermaid(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws IOException {
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

    private static class CallContext {
        final List<String> preview;
        final boolean truncated;

        CallContext(List<String> preview, boolean truncated) {
            this.preview = preview;
            this.truncated = truncated;
        }
    }

    private static class BlockSummary {
        final int count;
        final String firstMnemonic;
        final String lastMnemonic;
        final List<String> preview;
        final boolean truncated;
        final List<String> defsPreview;
        final boolean defsTruncated;
        final List<String> usesPreview;
        final boolean usesTruncated;
        final List<String> addressesPreview;
        final boolean addressesTruncated;
        final int callCount;
        final List<Map<String, Object>> callsitesPreview;
        final boolean callsitesTruncated;
        final int internalCallCount;
        final int externalCallsiteCount;
        final int indirectCallCount;
        final int thunkCallCount;
        final List<String> callTargets;
        final boolean callTargetsTruncated;
        final List<String> internalCallTargets;
        final boolean internalCallTargetsTruncated;
        final List<String> externalCallTargets;
        final boolean externalCallTargetsTruncated;
        final int memoryAccessCount;
        final List<Map<String, Object>> memoryAccessesPreview;
        final boolean memoryAccessesTruncated;
        final int memoryReadCount;
        final int memoryWriteCount;
        final int constantCount;
        final List<Map<String, Object>> constantsPreview;
        final boolean constantsTruncated;
        final int stringRefCount;
        final List<Map<String, Object>> stringRefsPreview;
        final boolean stringRefsTruncated;
        final int externalRefCount;
        final List<Map<String, Object>> externalRefsPreview;
        final boolean externalRefsTruncated;
        final int externalCallCount;
        final int externalAddressRefCount;
        final List<String> externalSymbols;
        final boolean externalSymbolsTruncated;
        final List<String> modules;
        final List<String> apiFamilies;
        final List<String> apiTags;
        final List<Map<String, Object>> ops;

        BlockSummary(
            int count,
            String firstMnemonic,
            String lastMnemonic,
            List<String> preview,
            boolean truncated,
            List<String> defsPreview,
            boolean defsTruncated,
            List<String> usesPreview,
            boolean usesTruncated,
            List<String> addressesPreview,
            boolean addressesTruncated,
            int callCount,
            List<Map<String, Object>> callsitesPreview,
            boolean callsitesTruncated,
            int internalCallCount,
            int externalCallsiteCount,
            int indirectCallCount,
            int thunkCallCount,
            List<String> callTargets,
            boolean callTargetsTruncated,
            List<String> internalCallTargets,
            boolean internalCallTargetsTruncated,
            List<String> externalCallTargets,
            boolean externalCallTargetsTruncated,
            int memoryAccessCount,
            List<Map<String, Object>> memoryAccessesPreview,
            boolean memoryAccessesTruncated,
            int memoryReadCount,
            int memoryWriteCount,
            int constantCount,
            List<Map<String, Object>> constantsPreview,
            boolean constantsTruncated,
            int stringRefCount,
            List<Map<String, Object>> stringRefsPreview,
            boolean stringRefsTruncated,
            int externalRefCount,
            List<Map<String, Object>> externalRefsPreview,
            boolean externalRefsTruncated,
            int externalCallCount,
            int externalAddressRefCount,
            List<String> externalSymbols,
            boolean externalSymbolsTruncated,
            List<String> modules,
            List<String> apiFamilies,
            List<String> apiTags,
            List<Map<String, Object>> ops
        ) {
            this.count = count;
            this.firstMnemonic = firstMnemonic;
            this.lastMnemonic = lastMnemonic;
            this.preview = preview;
            this.truncated = truncated;
            this.defsPreview = defsPreview;
            this.defsTruncated = defsTruncated;
            this.usesPreview = usesPreview;
            this.usesTruncated = usesTruncated;
            this.addressesPreview = addressesPreview;
            this.addressesTruncated = addressesTruncated;
            this.callCount = callCount;
            this.callsitesPreview = callsitesPreview;
            this.callsitesTruncated = callsitesTruncated;
            this.internalCallCount = internalCallCount;
            this.externalCallsiteCount = externalCallsiteCount;
            this.indirectCallCount = indirectCallCount;
            this.thunkCallCount = thunkCallCount;
            this.callTargets = callTargets;
            this.callTargetsTruncated = callTargetsTruncated;
            this.internalCallTargets = internalCallTargets;
            this.internalCallTargetsTruncated = internalCallTargetsTruncated;
            this.externalCallTargets = externalCallTargets;
            this.externalCallTargetsTruncated = externalCallTargetsTruncated;
            this.memoryAccessCount = memoryAccessCount;
            this.memoryAccessesPreview = memoryAccessesPreview;
            this.memoryAccessesTruncated = memoryAccessesTruncated;
            this.memoryReadCount = memoryReadCount;
            this.memoryWriteCount = memoryWriteCount;
            this.constantCount = constantCount;
            this.constantsPreview = constantsPreview;
            this.constantsTruncated = constantsTruncated;
            this.stringRefCount = stringRefCount;
            this.stringRefsPreview = stringRefsPreview;
            this.stringRefsTruncated = stringRefsTruncated;
            this.externalRefCount = externalRefCount;
            this.externalRefsPreview = externalRefsPreview;
            this.externalRefsTruncated = externalRefsTruncated;
            this.externalCallCount = externalCallCount;
            this.externalAddressRefCount = externalAddressRefCount;
            this.externalSymbols = externalSymbols;
            this.externalSymbolsTruncated = externalSymbolsTruncated;
            this.modules = modules;
            this.apiFamilies = apiFamilies;
            this.apiTags = apiTags;
            this.ops = ops;
        }
    }
}
