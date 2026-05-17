// Extract a basic-block control-flow graph for a function and write a JSON envelope to the path
// passed as the first script argument.
// Usage: <output_path> <name_or_address>
// name_or_address is parsed as an address first (AddressFactory.getAddress after stripping a
// leading 0x/0X), then resolved via FunctionManager.getFunctionContaining. On address-path
// failure it falls back to case-insensitive exact-then-partial match against the fully-qualified
// function name (Function.getName(true)).
// Blocks are walked via BasicBlockModel.getCodeBlocksContaining(function.getBody(), monitor).
// Flow edges are walked via CodeBlock.getDestinations(monitor) and classified by
// CodeBlockReference.getFlowType().getName().
// Always exits 0 and writes a valid envelope; lookup failures populate resolution_error and
// return a zero-block graph.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class cfg extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.cfg.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[cfg] missing args; expected <output_path> <name_or_address>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];

        if (currentProgram == null) {
            printerr("[cfg] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("resolution_error", "");
        envelope.put("block_count", 0L);
        envelope.put("edge_count", 0L);
        envelope.put("blocks", new ArrayList<Map<String, Object>>());
        envelope.put("edges", new ArrayList<Map<String, Object>>());
        envelope.put("mermaid", "graph TD");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function root;
        try {
            root = resolveFunction(fm, nameOrAddress);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeEnvelope(outputPath, envelope);
            println("[cfg] resolution failed for '" + nameOrAddress + "': " + re.getMessage());
            return;
        }

        if (root.getEntryPoint() == null) {
            envelope.put(
                "resolution_error",
                "Function '" + safeFullName(root) + "' has no entry-point address and cannot be walked."
            );
            envelope.put("resolved_function_name", safeFullName(root));
            writeEnvelope(outputPath, envelope);
            println("[cfg] refusing to walk " + safeFullName(root) + " with null entry point");
            return;
        }

        envelope.put("resolved_address", root.getEntryPoint().toString());
        envelope.put("resolved_function_name", safeFullName(root));

        LinkedHashMap<String, Map<String, Object>> blocksByAddr = new LinkedHashMap<>();
        LinkedHashSet<String> edgeKeys = new LinkedHashSet<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        AddressSetView body = root.getBody();
        Listing listing = currentProgram.getListing();

        CodeBlockIterator blockIter = bbm.getCodeBlocksContaining(body, monitor);
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            if (block == null) {
                continue;
            }
            Address start = block.getFirstStartAddress();
            if (start == null) {
                continue;
            }
            String startStr = start.toString();
            if (!blocksByAddr.containsKey(startStr)) {
                blocksByAddr.put(startStr, blockEntry(block, listing));
            }

            try {
                CodeBlockReferenceIterator destIter = block.getDestinations(monitor);
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    if (ref == null) {
                        continue;
                    }
                    Address destStart = ref.getDestinationAddress();
                    if (destStart == null) {
                        continue;
                    }
                    if (!body.contains(destStart)) {
                        continue;
                    }
                    String destStr = destStart.toString();
                    String flowName = flowTypeName(ref.getFlowType());
                    String edgeKey = startStr + "->" + destStr + "/" + flowName;
                    if (edgeKeys.contains(edgeKey)) {
                        continue;
                    }
                    edgeKeys.add(edgeKey);
                    Map<String, Object> edge = new LinkedHashMap<>();
                    edge.put("from", startStr);
                    edge.put("to", destStr);
                    edge.put("flow_type", flowName);
                    edges.add(edge);
                }
            } catch (Exception e) {
                printerr("[cfg] error walking destinations of block " + startStr + ": " + e.getMessage());
                continue;
            }
        }

        List<Map<String, Object>> blocks = new ArrayList<>(blocksByAddr.values());

        envelope.put("block_count", (long) blocks.size());
        envelope.put("edge_count", (long) edges.size());
        envelope.put("blocks", blocks);
        envelope.put("edges", edges);
        envelope.put("mermaid", renderMermaid(blocks, edges));

        writeEnvelope(outputPath, envelope);
        println("[cfg] rooted at " + safeFullName(root) + "; blocks=" + blocks.size()
            + ", edges=" + edges.size() + " -> " + outputPath);
    }

    private Map<String, Object> blockEntry(CodeBlock block, Listing listing) {
        Map<String, Object> entry = new LinkedHashMap<>();
        Address start = block.getFirstStartAddress();
        entry.put("address", start != null ? start.toString() : "");
        long size = 0L;
        try {
            size = block.getNumAddresses();
        } catch (Exception e) {
            size = 0L;
        }
        entry.put("size", size);
        long instructions = 0L;
        try {
            InstructionIterator it = listing.getInstructions(block, true);
            while (it.hasNext()) {
                Instruction insn = it.next();
                if (insn == null) {
                    continue;
                }
                instructions++;
            }
        } catch (Exception e) {
            instructions = 0L;
        }
        entry.put("instructions", instructions);
        return entry;
    }

    private String flowTypeName(FlowType ft) {
        if (ft == null) {
            return "UNKNOWN";
        }
        try {
            String name = ft.getName();
            if (name == null || name.isEmpty()) {
                return "UNKNOWN";
            }
            return name;
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private String safeName(Function func) {
        try {
            return func.getName();
        } catch (Exception e) {
            return "";
        }
    }

    private String safeFullName(Function func) {
        try {
            return func.getName(true);
        } catch (Exception e) {
            return safeName(func);
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

    private String renderMermaid(List<Map<String, Object>> blocks, List<Map<String, Object>> edges) {
        if (blocks.isEmpty()) {
            return "graph TD";
        }
        HashMap<String, String> idByAddr = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        sb.append("graph TD\n");
        int idx = 0;
        for (Map<String, Object> block : blocks) {
            String addr = String.valueOf(block.get("address"));
            String id = "b" + idx;
            idByAddr.put(addr, id);
            sb.append("  ").append(id).append("[\"").append(escapeMermaid(addr)).append("\"]\n");
            idx++;
        }
        for (Map<String, Object> edge : edges) {
            String from = String.valueOf(edge.get("from"));
            String to = String.valueOf(edge.get("to"));
            String fromId = idByAddr.get(from);
            String toId = idByAddr.get(to);
            if (fromId == null || toId == null) {
                continue;
            }
            sb.append("  ").append(fromId).append(" --> ").append(toId).append("\n");
        }
        return sb.toString();
    }

    private String escapeMermaid(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '"') {
                out.append("\\\"");
            } else if (c == '\n' || c == '\r') {
                out.append(' ');
            } else {
                out.append(c);
            }
        }
        return out.toString();
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
}
