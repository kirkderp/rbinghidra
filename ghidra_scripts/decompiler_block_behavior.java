// Extract decompiler-derived block behavior summaries for a function and write a JSON envelope to
// the path passed as the first script argument.
// Usage: <output_path> <name_or_address> [simplification_style] [only_strings] [only_external] [only_api_tag]
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

public class decompiler_block_behavior extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompiler_block_behavior.v0";
    private static final String SOURCE_SCHEMA = "rbm.ghidra.decompiler_cfg.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int PREVIEW_LIMIT = 6;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[decompiler_block_behavior] missing args; expected <output_path> <name_or_address> [simplification_style] [only_strings] [only_external] [only_api_tag]");
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String nameOrAddress = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;
        boolean onlyStrings = args.length >= 4 &&
            ("1".equals(args[3]) || "true".equalsIgnoreCase(args[3]));
        boolean onlyExternal = args.length >= 5 &&
            ("1".equals(args[4]) || "true".equalsIgnoreCase(args[4]));
        String onlyApiTag = args.length >= 6 ? args[5].trim().toLowerCase() : "";

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("source_schema", SOURCE_SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("block_count", 0);
        envelope.put("total_conditional_edge_count", 0);
        envelope.put("total_flow_edge_count", 0);
        envelope.put("total_back_edge_count", 0);
        envelope.put("blocks", new ArrayList<Map<String, Object>>());
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");

        if (currentProgram == null) {
            printerr("[decompiler_block_behavior] no program loaded");
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

        HashMap<Integer, EdgeSummary> edgeSummary = summarizeEdges(basicBlocks);
        List<Map<String, Object>> blocks = new ArrayList<>();
        int totalConditionalEdgeCount = 0;
        int totalFlowEdgeCount = 0;
        int totalBackEdgeCount = 0;

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            BehaviorSummary summary = summarizeBlock(block);
            if (onlyStrings && summary.stringRefCount == 0) {
                continue;
            }
            if (onlyExternal && summary.externalCallCount == 0) {
                continue;
            }
            if (!onlyApiTag.isEmpty() && !summary.apiTags.contains(onlyApiTag)) {
                continue;
            }

            EdgeSummary edge = edgeSummary.containsKey(block.getIndex())
                ? edgeSummary.get(block.getIndex())
                : new EdgeSummary();
            Map<String, Object> blockMap = new LinkedHashMap<>();
            blockMap.put("index", block.getIndex());
            blockMap.put("start", block.getStart() != null ? block.getStart().toString() : "");
            blockMap.put("stop", block.getStop() != null ? block.getStop().toString() : "");
            blockMap.put("block_kind", blockKind(block, predecessors, successors, byIndex));
            blockMap.put("structural_tags", structuralTags(block, predecessors, successors, byIndex));
            blockMap.put("predecessor_indices", toIntegerList(predecessors.get(block.getIndex())));
            blockMap.put("successor_indices", toIntegerList(successors.get(block.getIndex())));
            blockMap.put("incoming_edges", block.getInSize());
            blockMap.put("outgoing_edges", block.getOutSize());
            blockMap.put("conditional_edge_count", edge.conditionalEdgeCount);
            blockMap.put("flow_edge_count", edge.flowEdgeCount);
            blockMap.put("back_edge_count", edge.backEdgeCount);
            blockMap.put("module_count", summary.modules.size());
            blockMap.put("modules", sortedCopy(summary.modules));
            blockMap.put("api_family_count", summary.apiFamilies.size());
            blockMap.put("api_families", sortedCopy(summary.apiFamilies));
            blockMap.put("api_tag_count", summary.apiTags.size());
            blockMap.put("api_tags", sortedCopy(summary.apiTags));
            blockMap.put("external_call_count", summary.externalCallCount);
            blockMap.put("external_address_ref_count", summary.externalAddressRefCount);
            blockMap.put("external_symbol_count", summary.externalSymbols.size());
            blockMap.put("external_symbols", sortedCopy(summary.externalSymbols));
            blockMap.put("external_symbols_truncated", summary.externalSymbolsTruncated);
            blockMap.put("constant_count", summary.constantCount);
            blockMap.put("constants_preview", summary.constantsPreview);
            blockMap.put("constants_preview_truncated", summary.constantsTruncated);
            blockMap.put("string_ref_count", summary.stringRefCount);
            blockMap.put("string_refs_preview", summary.stringRefsPreview);
            blockMap.put("string_refs_preview_truncated", summary.stringRefsTruncated);
            blocks.add(blockMap);

            totalConditionalEdgeCount += edge.conditionalEdgeCount;
            totalFlowEdgeCount += edge.flowEdgeCount;
            totalBackEdgeCount += edge.backEdgeCount;
        }

        envelope.put("block_count", blocks.size());
        envelope.put("total_conditional_edge_count", totalConditionalEdgeCount);
        envelope.put("total_flow_edge_count", totalFlowEdgeCount);
        envelope.put("total_back_edge_count", totalBackEdgeCount);
        envelope.put("blocks", blocks);
        writeEnvelope(outputPath, envelope);
    }

    private HashMap<Integer, EdgeSummary> summarizeEdges(ArrayList<PcodeBlockBasic> basicBlocks) {
        HashMap<Integer, EdgeSummary> byBlock = new HashMap<>();
        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            EdgeSummary summary = new EdgeSummary();
            for (int i = 0; i < block.getOutSize(); i++) {
                PcodeBlock out = block.getOut(i);
                if (!(out instanceof PcodeBlockBasic)) {
                    continue;
                }
                PcodeBlockBasic dest = (PcodeBlockBasic) out;
                String branchKind = branchKind(block, i);
                if (branchKind.startsWith("conditional_")) {
                    summary.conditionalEdgeCount++;
                }
                if ("flow".equals(branchKind)) {
                    summary.flowEdgeCount++;
                }
                if (dest.getIndex() <= block.getIndex()) {
                    summary.backEdgeCount++;
                }
            }
            byBlock.put(block.getIndex(), summary);
        }
        return byBlock;
    }

    private BehaviorSummary summarizeBlock(PcodeBlockBasic block) {
        LinkedHashMap<String, Map<String, Object>> constants = new LinkedHashMap<>();
        LinkedHashMap<String, Map<String, Object>> stringRefs = new LinkedHashMap<>();
        LinkedHashMap<String, Map<String, Object>> externalRefs = new LinkedHashMap<>();
        LinkedHashSet<String> externalSymbols = new LinkedHashSet<>();
        LinkedHashSet<String> modules = new LinkedHashSet<>();
        LinkedHashSet<String> apiFamilies = new LinkedHashSet<>();
        LinkedHashSet<String> apiTags = new LinkedHashSet<>();
        int externalCallCount = 0;
        int externalAddressRefCount = 0;

        Iterator<PcodeOp> it = block.getIterator();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            if (op == null) {
                continue;
            }
            String mnemonic = safeMnemonic(op);
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (in != null) {
                    if (in.isConstant()) {
                        String key = constantKey(in);
                        if (!constants.containsKey(key)) {
                            constants.put(key, formatConstant(in, mnemonic));
                        }
                    }
                    captureStringRef(stringRefs, in, mnemonic);
                }
            }
            if (op.getOutput() != null) {
                captureStringRef(stringRefs, op.getOutput(), mnemonic);
            }
            captureExternalRefs(externalRefs, op, mnemonic);
            externalCallCount = countExternalRefsByKind(externalRefs, "call_target");
            externalAddressRefCount = countExternalRefsByKind(externalRefs, "address_ref");
            captureExternalSymbols(externalSymbols, externalRefs);
            captureModules(modules, externalRefs);
            captureApiFamilies(apiFamilies, externalRefs);
            captureApiTags(apiTags, externalRefs);
        }

        return new BehaviorSummary(
            constants.size(),
            truncateConstantPreview(constants),
            constants.size() > PREVIEW_LIMIT,
            stringRefs.size(),
            truncateStringRefPreview(stringRefs),
            stringRefs.size() > PREVIEW_LIMIT,
            externalCallCount,
            externalAddressRefCount,
            externalSymbols,
            externalSymbols.size() > PREVIEW_LIMIT,
            modules,
            apiFamilies,
            apiTags
        );
    }

    private String constantKey(Varnode vn) {
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
            if (count >= PREVIEW_LIMIT) {
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
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("value", valueObj);
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
            if (count >= PREVIEW_LIMIT) {
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
            String key = "call:" + ref.get("name") + "@" + ref.get("address");
            if (!externalRefs.containsKey(key)) {
                externalRefs.put(key, ref);
            }
        }
        for (int i = 0; i < op.getNumInputs(); i++) {
            captureExternalAddressRef(externalRefs, op.getInput(i), sourceOpMnemonic);
        }
        captureExternalAddressRef(externalRefs, op.getOutput(), sourceOpMnemonic);
    }

    private void captureExternalAddressRef(
        LinkedHashMap<String, Map<String, Object>> externalRefs,
        Varnode vn,
        String sourceOpMnemonic
    ) {
        Map<String, Object> ref = formatExternalAddressRef(vn, sourceOpMnemonic);
        if (ref == null) {
            return;
        }
        String key = "addr:" + ref.get("name") + "@" + ref.get("address");
        if (!externalRefs.containsKey(key)) {
            externalRefs.put(key, ref);
        }
    }

    private Map<String, Object> formatExternalAddressRef(Varnode vn, String sourceOpMnemonic) {
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
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private void captureExternalSymbols(LinkedHashSet<String> externalSymbols, LinkedHashMap<String, Map<String, Object>> externalRefs) {
        externalSymbols.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object nameObj = ref.get("name");
            if (nameObj instanceof String) {
                String name = ((String) nameObj).trim();
                if (!name.isEmpty()) {
                    externalSymbols.add(name);
                }
            }
        }
    }

    private void captureModules(LinkedHashSet<String> modules, LinkedHashMap<String, Map<String, Object>> externalRefs) {
        modules.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object moduleObj = ref.get("module_name");
            if (moduleObj instanceof String) {
                String module = ((String) moduleObj).trim();
                if (!module.isEmpty()) {
                    modules.add(module);
                }
            }
        }
    }

    private void captureApiFamilies(LinkedHashSet<String> apiFamilies, LinkedHashMap<String, Map<String, Object>> externalRefs) {
        apiFamilies.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object moduleObj = ref.get("module_name");
            if (moduleObj instanceof String) {
                String family = classifyApiFamily((String) moduleObj);
                if (!family.isEmpty()) {
                    apiFamilies.add(family);
                }
            }
        }
    }

    private void captureApiTags(LinkedHashSet<String> apiTags, LinkedHashMap<String, Map<String, Object>> externalRefs) {
        apiTags.clear();
        for (Map<String, Object> ref : externalRefs.values()) {
            Object nameObj = ref.get("name");
            Object moduleObj = ref.get("module_name");
            String tag = classifyApiTag(
                nameObj instanceof String ? (String) nameObj : "",
                moduleObj instanceof String ? (String) moduleObj : ""
            );
            if (!tag.isEmpty()) {
                apiTags.add(tag.toLowerCase());
            }
        }
    }

    private int countExternalRefsByKind(LinkedHashMap<String, Map<String, Object>> externalRefs, String refKind) {
        int count = 0;
        for (Map<String, Object> ref : externalRefs.values()) {
            Object kindObj = ref.get("ref_kind");
            if (kindObj instanceof String && refKind.equals(kindObj)) {
                count++;
            }
        }
        return count;
    }

    private List<Integer> toIntegerList(LinkedHashSet<Integer> items) {
        List<Integer> out = new ArrayList<>();
        if (items != null) {
            out.addAll(items);
        }
        return out;
    }

    private List<String> sortedCopy(LinkedHashSet<String> values) {
        List<String> out = new ArrayList<>(values);
        Collections.sort(out);
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
        if (succCount == 0 || "return".equals(branchKind(block, 0))) {
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

    private String branchKind(PcodeBlockBasic block, int outIndex) {
        PcodeOp lastOp = block != null ? block.getLastOp() : null;
        if (lastOp == null) {
            return "flow";
        }
        switch (lastOp.getOpcode()) {
            case PcodeOp.CBRANCH:
                return outIndex == 0 ? "conditional_false" : "conditional_true";
            case PcodeOp.BRANCH:
                return "jump";
            case PcodeOp.BRANCHIND:
                return "indirect_jump";
            case PcodeOp.RETURN:
                return "return";
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
                return "call";
            default:
                return "flow";
        }
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

    private static class EdgeSummary {
        int conditionalEdgeCount;
        int flowEdgeCount;
        int backEdgeCount;
    }

    private static class BehaviorSummary {
        final int constantCount;
        final List<Map<String, Object>> constantsPreview;
        final boolean constantsTruncated;
        final int stringRefCount;
        final List<Map<String, Object>> stringRefsPreview;
        final boolean stringRefsTruncated;
        final int externalCallCount;
        final int externalAddressRefCount;
        final LinkedHashSet<String> externalSymbols;
        final boolean externalSymbolsTruncated;
        final LinkedHashSet<String> modules;
        final LinkedHashSet<String> apiFamilies;
        final LinkedHashSet<String> apiTags;

        BehaviorSummary(
            int constantCount,
            List<Map<String, Object>> constantsPreview,
            boolean constantsTruncated,
            int stringRefCount,
            List<Map<String, Object>> stringRefsPreview,
            boolean stringRefsTruncated,
            int externalCallCount,
            int externalAddressRefCount,
            LinkedHashSet<String> externalSymbols,
            boolean externalSymbolsTruncated,
            LinkedHashSet<String> modules,
            LinkedHashSet<String> apiFamilies,
            LinkedHashSet<String> apiTags
        ) {
            this.constantCount = constantCount;
            this.constantsPreview = constantsPreview;
            this.constantsTruncated = constantsTruncated;
            this.stringRefCount = stringRefCount;
            this.stringRefsPreview = stringRefsPreview;
            this.stringRefsTruncated = stringRefsTruncated;
            this.externalCallCount = externalCallCount;
            this.externalAddressRefCount = externalAddressRefCount;
            this.externalSymbols = externalSymbols;
            this.externalSymbolsTruncated = externalSymbolsTruncated;
            this.modules = modules;
            this.apiFamilies = apiFamilies;
            this.apiTags = apiTags;
        }
    }
}
