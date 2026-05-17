// Extract decompiler-derived call summaries for a function and write a JSON envelope to the path
// passed as the first script argument.
// Usage: <output_path> <name_or_address> [simplification_style] [only_external] [only_indirect] [only_api_tag]
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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class decompiler_calls extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompiler_calls.v0";
    private static final String SOURCE_SCHEMA = "rbm.ghidra.decompiler_cfg.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int PREVIEW_LIMIT = 6;
    private static final int ADDRESS_PREVIEW_LIMIT = 6;
    private static final int CALL_CONTEXT_PREVIEW_LIMIT = 10;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[decompiler_calls] missing args; expected <output_path> <name_or_address> [simplification_style] [only_external] [only_indirect] [only_api_tag]");
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String nameOrAddress = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;
        boolean onlyExternal = args.length >= 4 &&
            ("1".equals(args[3]) || "true".equalsIgnoreCase(args[3]));
        boolean onlyIndirect = args.length >= 5 &&
            ("1".equals(args[4]) || "true".equalsIgnoreCase(args[4]));
        String onlyApiTag = args.length >= 6 ? args[5].trim().toLowerCase() : "";

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("source_schema", SOURCE_SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("source_block_count", 0);
        envelope.put("matched_block_count", 0);
        envelope.put("total_call_count", 0);
        envelope.put("total_internal_call_count", 0);
        envelope.put("total_external_callsite_count", 0);
        envelope.put("total_indirect_call_count", 0);
        envelope.put("total_thunk_call_count", 0);
        envelope.put("blocks", new ArrayList<Map<String, Object>>());
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");

        if (currentProgram == null) {
            printerr("[decompiler_calls] no program loaded");
            throw new IllegalStateException("no program");
        }

        Function root;
        try {
            root = resolveFunction(currentProgram.getFunctionManager(), nameOrAddress);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeEnvelope(outputPath, envelope);
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
        envelope.put("source_block_count", basicBlocks.size());

        HashMap<Integer, PcodeBlockBasic> byIndex = new HashMap<>();
        HashMap<Integer, LinkedHashSet<Integer>> predecessors = new HashMap<>();
        HashMap<Integer, LinkedHashSet<Integer>> successors = new HashMap<>();
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

        List<Map<String, Object>> blocks = new ArrayList<>();
        int totalCallCount = 0;
        int totalInternalCallCount = 0;
        int totalExternalCallsiteCount = 0;
        int totalIndirectCallCount = 0;
        int totalThunkCallCount = 0;

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            CallsBlockSummary summary = summarizeBlock(block);
            if (summary.callCount == 0) {
                continue;
            }
            if (onlyExternal && summary.externalCallsiteCount == 0) {
                continue;
            }
            if (onlyIndirect && summary.indirectCallCount == 0) {
                continue;
            }
            if (!onlyApiTag.isEmpty() && !summary.apiTags.contains(onlyApiTag)) {
                continue;
            }

            Map<String, Object> blockMap = new LinkedHashMap<>();
            blockMap.put("index", block.getIndex());
            blockMap.put("start", block.getStart() != null ? block.getStart().toString() : "");
            blockMap.put("stop", block.getStop() != null ? block.getStop().toString() : "");
            blockMap.put("block_kind", blockKind(block, predecessors, successors, byIndex));
            blockMap.put("structural_tags", structuralTags(block, predecessors, successors, byIndex));
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
            blockMap.put("call_targets", sortedCopy(summary.callTargets));
            blockMap.put("call_targets_truncated", summary.callTargetsTruncated);
            blockMap.put("internal_call_target_count", summary.internalCallTargets.size());
            blockMap.put("internal_call_targets", sortedCopy(summary.internalCallTargets));
            blockMap.put("internal_call_targets_truncated", summary.internalCallTargetsTruncated);
            blockMap.put("external_call_target_count", summary.externalCallTargets.size());
            blockMap.put("external_call_targets", sortedCopy(summary.externalCallTargets));
            blockMap.put("external_call_targets_truncated", summary.externalCallTargetsTruncated);
            blocks.add(blockMap);

            totalCallCount += summary.callCount;
            totalInternalCallCount += summary.internalCallCount;
            totalExternalCallsiteCount += summary.externalCallsiteCount;
            totalIndirectCallCount += summary.indirectCallCount;
            totalThunkCallCount += summary.thunkCallCount;
        }

        envelope.put("matched_block_count", blocks.size());
        envelope.put("total_call_count", totalCallCount);
        envelope.put("total_internal_call_count", totalInternalCallCount);
        envelope.put("total_external_callsite_count", totalExternalCallsiteCount);
        envelope.put("total_indirect_call_count", totalIndirectCallCount);
        envelope.put("total_thunk_call_count", totalThunkCallCount);
        envelope.put("blocks", blocks);
        writeEnvelope(outputPath, envelope);
    }

    private CallsBlockSummary summarizeBlock(PcodeBlockBasic block) {
        LinkedHashSet<String> addresses = new LinkedHashSet<>();
        List<Map<String, Object>> callsites = new ArrayList<>();
        boolean callsitesTruncated = false;
        int callCount = 0;
        int internalCallCount = 0;
        int externalCallsiteCount = 0;
        int indirectCallCount = 0;
        int thunkCallCount = 0;
        LinkedHashSet<String> callTargets = new LinkedHashSet<>();
        LinkedHashSet<String> internalCallTargets = new LinkedHashSet<>();
        LinkedHashSet<String> externalCallTargets = new LinkedHashSet<>();
        LinkedHashSet<String> apiTags = new LinkedHashSet<>();

        Iterator<PcodeOp> it = block.getIterator();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            if (op == null) {
                continue;
            }
            String opAddress = opAddress(op);
            if (!opAddress.isEmpty()) {
                addresses.add(opAddress);
            }
            if (!isCallOp(op)) {
                continue;
            }
            callCount++;
            Map<String, Object> callsite = formatCallsite(block, op);
            boolean isExternal = Boolean.TRUE.equals(callsite.get("is_external"));
            boolean isIndirect = Boolean.TRUE.equals(callsite.get("is_indirect"));
            boolean isThunk = Boolean.TRUE.equals(callsite.get("is_thunk"));
            String apiTag = stringField(callsite.get("api_tag"));
            if (!apiTag.isEmpty()) {
                apiTags.add(apiTag.toLowerCase());
            }
            if (isExternal) {
                externalCallsiteCount++;
                captureTypedCallTarget(externalCallTargets, callsite);
            } else {
                internalCallCount++;
                captureTypedCallTarget(internalCallTargets, callsite);
            }
            if (isIndirect) {
                indirectCallCount++;
            }
            if (isThunk) {
                thunkCallCount++;
            }
            captureTypedCallTarget(callTargets, callsite);
            if (callsites.size() < PREVIEW_LIMIT) {
                callsites.add(callsite);
            } else {
                callsitesTruncated = true;
            }
        }

        return new CallsBlockSummary(
            truncateAddressPreview(addresses),
            addresses.size() > ADDRESS_PREVIEW_LIMIT,
            callCount,
            callsites,
            callsitesTruncated,
            internalCallCount,
            externalCallsiteCount,
            indirectCallCount,
            thunkCallCount,
            callTargets,
            callTargets.size() > PREVIEW_LIMIT,
            internalCallTargets,
            internalCallTargets.size() > PREVIEW_LIMIT,
            externalCallTargets,
            externalCallTargets.size() > PREVIEW_LIMIT,
            apiTags
        );
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

    private String stringField(Object value) {
        return value instanceof String ? ((String) value).trim() : "";
    }

    private List<String> sortedCopy(LinkedHashSet<String> values) {
        List<String> out = new ArrayList<>(values);
        Collections.sort(out);
        return out;
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

    private String normalizeModuleName(String moduleName) {
        if (moduleName == null) {
            return "";
        }
        return moduleName.trim().toLowerCase();
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
                Address opAddr = currentProgram.getAddressFactory().getAddress(addr);
                Instruction instr = getInstructionAt(opAddr);
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
        } catch (Exception e) {
            name = "varnode";
        }
        return name + "<" + storage + ">";
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
        if (succCount == 0) {
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
        return tags;
    }

    private boolean isBackEdge(PcodeBlockBasic from, PcodeBlockBasic to) {
        if (from == null || to == null || from.getStart() == null || to.getStart() == null) {
            return false;
        }
        return from.getStart().compareTo(to.getStart()) >= 0;
    }

    private String opAddress(PcodeOp op) {
        if (op == null || op.getSeqnum() == null || op.getSeqnum().getTarget() == null) {
            return "";
        }
        return op.getSeqnum().getTarget().toString();
    }

    private String safeFullName(Function func) {
        if (func == null) {
            return "";
        }
        try {
            String name = func.getName(true);
            return name != null ? name : "";
        } catch (Exception e) {
            String name = func.getName();
            return name != null ? name : "";
        }
    }

    private Function resolveFunction(FunctionManager fm, String nameOrAddress) throws ResolutionException {
        String query = nameOrAddress != null ? nameOrAddress.trim() : "";
        if (query.isEmpty()) {
            throw new ResolutionException("empty query");
        }

        AddressFactory af = currentProgram.getAddressFactory();
        String addrQuery = stripHexPrefix(query);
        if (!addrQuery.isEmpty()) {
            try {
                Address addr = af.getAddress(addrQuery);
                if (addr != null) {
                    Function at = fm.getFunctionAt(addr);
                    if (at != null) {
                        return at;
                    }
                    Function containing = fm.getFunctionContaining(addr);
                    if (containing != null) {
                        return containing;
                    }
                }
            } catch (Exception e) {
            }
        }

        List<Function> exact = new ArrayList<>();
        List<Function> partial = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            String fullName = safeFullName(fn);
            if (fullName.equalsIgnoreCase(query)) {
                exact.add(fn);
            } else if (fullName.toLowerCase().contains(query.toLowerCase())) {
                partial.add(fn);
            }
        }
        if (exact.size() == 1) {
            return exact.get(0);
        }
        if (exact.size() > 1) {
            throw new ResolutionException("Ambiguous function name '" + query + "'");
        }
        if (partial.size() == 1) {
            return partial.get(0);
        }
        if (partial.size() > 1) {
            throw new ResolutionException("Ambiguous function name '" + query + "'");
        }
        throw new ResolutionException("Function '" + query + "' not found.");
    }

    private String stripHexPrefix(String s) {
        if (s == null) {
            return "";
        }
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return s.substring(2);
        }
        return s;
    }

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws IOException {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Path out = Paths.get(outputPath);
        Files.createDirectories(out.getParent());
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(out, StandardCharsets.UTF_8))) {
            pw.write(gson.toJson(envelope));
        }
    }

    private static class ResolutionException extends Exception {
        ResolutionException(String message) {
            super(message);
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

    private static class CallsBlockSummary {
        final List<String> addressesPreview;
        final boolean addressesTruncated;
        final int callCount;
        final List<Map<String, Object>> callsitesPreview;
        final boolean callsitesTruncated;
        final int internalCallCount;
        final int externalCallsiteCount;
        final int indirectCallCount;
        final int thunkCallCount;
        final LinkedHashSet<String> callTargets;
        final boolean callTargetsTruncated;
        final LinkedHashSet<String> internalCallTargets;
        final boolean internalCallTargetsTruncated;
        final LinkedHashSet<String> externalCallTargets;
        final boolean externalCallTargetsTruncated;
        final LinkedHashSet<String> apiTags;

        CallsBlockSummary(
            List<String> addressesPreview,
            boolean addressesTruncated,
            int callCount,
            List<Map<String, Object>> callsitesPreview,
            boolean callsitesTruncated,
            int internalCallCount,
            int externalCallsiteCount,
            int indirectCallCount,
            int thunkCallCount,
            LinkedHashSet<String> callTargets,
            boolean callTargetsTruncated,
            LinkedHashSet<String> internalCallTargets,
            boolean internalCallTargetsTruncated,
            LinkedHashSet<String> externalCallTargets,
            boolean externalCallTargetsTruncated,
            LinkedHashSet<String> apiTags
        ) {
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
            this.apiTags = apiTags;
        }
    }
}
