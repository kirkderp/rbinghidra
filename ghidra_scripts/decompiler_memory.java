// Extract decompiler-derived memory summaries for a function and write a JSON envelope to the
// path passed as the first script argument.
// Usage: <output_path> <name_or_address> [simplification_style] [only_writes]
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
import ghidra.program.model.pcode.HighFunction;
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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class decompiler_memory extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.decompiler_memory.v0";
    private static final String SOURCE_SCHEMA = "rbm.ghidra.decompiler_cfg.v0";
    private static final String DEFAULT_SIMPLIFICATION_STYLE = "decompile";
    private static final int PREVIEW_LIMIT = 6;
    private static final int ADDRESS_PREVIEW_LIMIT = 6;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[decompiler_memory] missing args; expected <output_path> <name_or_address> [simplification_style] [only_writes]");
            throw new IllegalArgumentException("missing args");
        }

        String outputPath = args[0];
        String nameOrAddress = args[1];
        String simplificationStyle = args.length >= 3 ? args[2] : DEFAULT_SIMPLIFICATION_STYLE;
        boolean onlyWrites = args.length >= 4 &&
            ("1".equals(args[3]) || "true".equalsIgnoreCase(args[3]));

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("source_schema", SOURCE_SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("simplification_style", simplificationStyle);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("source_block_count", 0);
        envelope.put("matched_block_count", 0);
        envelope.put("total_memory_access_count", 0);
        envelope.put("total_memory_read_count", 0);
        envelope.put("total_memory_write_count", 0);
        envelope.put("blocks", new ArrayList<Map<String, Object>>());
        envelope.put("decompile_completed", false);
        envelope.put("decompile_valid", false);
        envelope.put("is_timed_out", false);
        envelope.put("is_cancelled", false);
        envelope.put("failed_to_start", false);
        envelope.put("decompile_error", "");
        envelope.put("resolution_error", "");

        if (currentProgram == null) {
            printerr("[decompiler_memory] no program loaded");
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

        List<Map<String, Object>> blocks = new ArrayList<>();
        int totalMemoryAccessCount = 0;
        int totalMemoryReadCount = 0;
        int totalMemoryWriteCount = 0;

        for (PcodeBlockBasic block : basicBlocks) {
            if (block == null) {
                continue;
            }
            MemorySummary summary = summarizeBlock(block);
            if (summary.memoryAccessCount == 0) {
                continue;
            }
            if (onlyWrites && summary.memoryWriteCount == 0) {
                continue;
            }

            Map<String, Object> blockMap = new LinkedHashMap<>();
            blockMap.put("index", block.getIndex());
            blockMap.put("start", block.getStart() != null ? block.getStart().toString() : "");
            blockMap.put("stop", block.getStop() != null ? block.getStop().toString() : "");
            blockMap.put("block_kind", memoryBlockKind(summary));
            blockMap.put("structural_tags", memoryStructuralTags(summary));
            blockMap.put("instruction_addresses_preview", summary.addressesPreview);
            blockMap.put("instruction_addresses_truncated", summary.addressesTruncated);
            blockMap.put("memory_access_count", summary.memoryAccessCount);
            blockMap.put("memory_accesses_preview", summary.memoryAccessesPreview);
            blockMap.put("memory_accesses_preview_truncated", summary.memoryAccessesTruncated);
            blockMap.put("memory_read_count", summary.memoryReadCount);
            blockMap.put("memory_write_count", summary.memoryWriteCount);
            blocks.add(blockMap);

            totalMemoryAccessCount += summary.memoryAccessCount;
            totalMemoryReadCount += summary.memoryReadCount;
            totalMemoryWriteCount += summary.memoryWriteCount;
        }

        envelope.put("matched_block_count", blocks.size());
        envelope.put("total_memory_access_count", totalMemoryAccessCount);
        envelope.put("total_memory_read_count", totalMemoryReadCount);
        envelope.put("total_memory_write_count", totalMemoryWriteCount);
        envelope.put("blocks", blocks);
        writeEnvelope(outputPath, envelope);
    }

    private MemorySummary summarizeBlock(PcodeBlockBasic block) {
        LinkedHashSet<String> addresses = new LinkedHashSet<>();
        List<Map<String, Object>> memoryAccesses = new ArrayList<>();
        boolean memoryAccessesTruncated = false;
        int memoryAccessCount = 0;
        int memoryReadCount = 0;
        int memoryWriteCount = 0;

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
            List<Map<String, Object>> opMemoryAccesses = formatMemoryAccesses(op);
            for (Map<String, Object> access : opMemoryAccesses) {
                memoryAccessCount++;
                if ("write".equals(access.get("access_kind"))) {
                    memoryWriteCount++;
                } else {
                    memoryReadCount++;
                }
                if (memoryAccesses.size() < PREVIEW_LIMIT) {
                    memoryAccesses.add(access);
                } else {
                    memoryAccessesTruncated = true;
                }
            }
        }

        return new MemorySummary(
            truncateAddressPreview(addresses),
            addresses.size() > ADDRESS_PREVIEW_LIMIT,
            memoryAccessCount,
            memoryAccesses,
            memoryAccessesTruncated,
            memoryReadCount,
            memoryWriteCount
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

    private String memoryBlockKind(MemorySummary summary) {
        if (summary.memoryReadCount > 0 && summary.memoryWriteCount > 0) {
            return "read_write";
        }
        if (summary.memoryWriteCount > 0) {
            return "write_only";
        }
        return "read_only";
    }

    private List<String> memoryStructuralTags(MemorySummary summary) {
        List<String> tags = new ArrayList<>();
        if (summary.memoryReadCount > 0) {
            tags.add("memory_read");
        }
        if (summary.memoryWriteCount > 0) {
            tags.add("memory_write");
        }
        return tags;
    }

    private String memorySpaceKind(Varnode vn) {
        if (vn == null) {
            return "";
        }
        try {
            if (vn.getAddress() != null && vn.getAddress().getAddressSpace() != null) {
                String spaceName = vn.getAddress().getAddressSpace().getName();
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
            if (vn.getAddress() != null && vn.getAddress().isStackAddress()) {
                return "stack";
            }
            if (vn.isRegister()) {
                return "register";
            }
            if (vn.isUnique()) {
                return "unique";
            }
            if (vn.isAddress()) {
                return "ram";
            }
            if (vn.isConstant()) {
                return "constant";
            }
        } catch (Exception e) {
            return "";
        }
        return "";
    }

    private String formatVarnode(Varnode vn) {
        if (vn == null) {
            return "";
        }
        try {
            return vn.encodePiece();
        } catch (Exception e) {
            if (vn.getAddress() != null) {
                return vn.getAddress().toString();
            }
            return "";
        }
    }

    private String opAddress(PcodeOp op) {
        if (op == null || op.getSeqnum() == null || op.getSeqnum().getTarget() == null) {
            return "";
        }
        return op.getSeqnum().getTarget().toString();
    }

    private Function resolveFunction(FunctionManager fm, String query) throws ResolutionException {
        String trimmed = query == null ? "" : query.trim();
        if (trimmed.isEmpty()) {
            throw new ResolutionException("empty function query");
        }

        Function byAddress = resolveFunctionByAddress(fm, trimmed);
        if (byAddress != null) {
            return byAddress;
        }

        List<Function> exact = new ArrayList<>();
        List<Function> partial = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            String full = safeFullName(fn);
            if (full.equalsIgnoreCase(trimmed)) {
                exact.add(fn);
            } else if (full.toLowerCase().contains(trimmed.toLowerCase())) {
                partial.add(fn);
            }
        }
        if (exact.size() == 1) {
            return exact.get(0);
        }
        if (exact.size() > 1) {
            throw new ResolutionException("ambiguous function name '" + trimmed + "'");
        }
        if (partial.size() == 1) {
            return partial.get(0);
        }
        if (partial.size() > 1) {
            throw new ResolutionException("ambiguous function name '" + trimmed + "'");
        }
        throw new ResolutionException("function not found: " + trimmed);
    }

    private Function resolveFunctionByAddress(FunctionManager fm, String query) {
        try {
            String raw = query.startsWith("0x") || query.startsWith("0X") ? query.substring(2) : query;
            AddressFactory af = currentProgram.getAddressFactory();
            Address addr = af.getAddress(raw);
            if (addr == null) {
                return null;
            }
            return fm.getFunctionContaining(addr);
        } catch (Exception e) {
            return null;
        }
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

    private void writeEnvelope(String outputPath, Map<String, Object> envelope) throws IOException {
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Path out = Paths.get(outputPath);
        Path parent = out.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(
            out,
            StandardCharsets.UTF_8
        ))) {
            writer.write(gson.toJson(envelope));
        }
    }

    private static final class MemorySummary {
        final List<String> addressesPreview;
        final boolean addressesTruncated;
        final int memoryAccessCount;
        final List<Map<String, Object>> memoryAccessesPreview;
        final boolean memoryAccessesTruncated;
        final int memoryReadCount;
        final int memoryWriteCount;

        MemorySummary(
            List<String> addressesPreview,
            boolean addressesTruncated,
            int memoryAccessCount,
            List<Map<String, Object>> memoryAccessesPreview,
            boolean memoryAccessesTruncated,
            int memoryReadCount,
            int memoryWriteCount
        ) {
            this.addressesPreview = addressesPreview;
            this.addressesTruncated = addressesTruncated;
            this.memoryAccessCount = memoryAccessCount;
            this.memoryAccessesPreview = memoryAccessesPreview;
            this.memoryAccessesTruncated = memoryAccessesTruncated;
            this.memoryReadCount = memoryReadCount;
            this.memoryWriteCount = memoryWriteCount;
        }
    }

    private static final class ResolutionException extends Exception {
        ResolutionException(String message) {
            super(message);
        }
    }
}
