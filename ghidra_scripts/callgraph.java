// Generate a call graph for a function and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <name_or_address> [direction] [depth] [max_nodes]
// direction: "calling" (outgoing - functions this one calls) or "called" (incoming - functions that call this one).
// depth: max BFS hops from the root; 0 means unbounded walk until nothing new.
// max_nodes: hard cap on the number of nodes walked; BFS stops and truncated=true when reached.
// name_or_address is parsed as an address first (AddressFactory.getAddress after stripping a leading 0x/0X),
// then resolved via FunctionManager.getFunctionContaining. On address-path failure it falls back to case-insensitive
// exact-then-partial match against the fully-qualified function name (Function.getName(true)).
// Always exits 0 and writes a valid envelope; lookup failures populate resolution_error and return a zero-node graph.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public class callgraph extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.callgraph.v0";
    private static final String DEFAULT_DIRECTION = "calling";
    private static final long DEFAULT_DEPTH = 0L;
    private static final long DEFAULT_MAX_NODES = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[callgraph] missing args; expected <output_path> <name_or_address> [direction] [depth] [max_nodes]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];
        String direction = parseDirection(args, 2);
        long depth = parseLong(args, 3, DEFAULT_DEPTH);
        if (depth < 0L) {
            depth = 0L;
        }
        long maxNodes = parseLong(args, 4, DEFAULT_MAX_NODES);
        if (maxNodes < 1L) {
            maxNodes = 1L;
        }

        if (currentProgram == null) {
            printerr("[callgraph] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("direction", direction);
        envelope.put("depth", depth);
        envelope.put("resolved_address", "");
        envelope.put("resolved_function_name", "");
        envelope.put("resolution_error", "");
        envelope.put("truncated", Boolean.FALSE);
        envelope.put("node_count", 0L);
        envelope.put("edge_count", 0L);
        envelope.put("nodes", new ArrayList<Map<String, Object>>());
        envelope.put("edges", new ArrayList<Map<String, Object>>());
        envelope.put("mermaid", "");

        FunctionManager fm = currentProgram.getFunctionManager();
        Function root;
        try {
            root = resolveFunction(fm, nameOrAddress);
        } catch (ResolutionException re) {
            envelope.put("resolution_error", re.getMessage());
            writeEnvelope(outputPath, envelope);
            println("[callgraph] resolution failed for '" + nameOrAddress + "': " + re.getMessage());
            return;
        }

        if (root.getEntryPoint() == null) {
            envelope.put(
                "resolution_error",
                "Function '" + safeFullName(root) + "' has no entry-point address and cannot be walked."
            );
            envelope.put("resolved_function_name", safeFullName(root));
            writeEnvelope(outputPath, envelope);
            println("[callgraph] refusing to walk " + safeFullName(root) + " with null entry point");
            return;
        }

        envelope.put("resolved_address", root.getEntryPoint().toString());
        envelope.put("resolved_function_name", safeFullName(root));

        LinkedHashMap<String, Map<String, Object>> nodesByAddr = new LinkedHashMap<>();
        LinkedHashSet<String> edgeKeys = new LinkedHashSet<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        boolean truncated = walkBfs(root, direction, depth, maxNodes, nodesByAddr, edgeKeys, edges);

        List<Map<String, Object>> nodes = new ArrayList<>(nodesByAddr.values());

        envelope.put("truncated", Boolean.valueOf(truncated));
        envelope.put("node_count", (long) nodes.size());
        envelope.put("edge_count", (long) edges.size());
        envelope.put("nodes", nodes);
        envelope.put("edges", edges);
        envelope.put("mermaid", renderMermaid(nodes, edges, direction));

        writeEnvelope(outputPath, envelope);
        println("[callgraph] rooted at " + safeFullName(root) + " (direction=" + direction
            + ", depth=" + depth + ", max_nodes=" + maxNodes + "); nodes=" + nodes.size()
            + ", edges=" + edges.size() + ", truncated=" + truncated + " -> " + outputPath);
    }

    private boolean walkBfs(
        Function root,
        String direction,
        long depth,
        long maxNodes,
        LinkedHashMap<String, Map<String, Object>> nodesByAddr,
        LinkedHashSet<String> edgeKeys,
        List<Map<String, Object>> edges
    ) {
        String rootAddr = root.getEntryPoint() != null ? root.getEntryPoint().toString() : "";
        nodesByAddr.put(rootAddr, nodeFor(root));

        Deque<Function> frontier = new ArrayDeque<>();
        Deque<Long> frontierDepth = new ArrayDeque<>();
        frontier.add(root);
        frontierDepth.add(0L);
        boolean truncated = false;

        while (!frontier.isEmpty()) {
            Function current = frontier.poll();
            long currentDepth = frontierDepth.poll();
            if (depth > 0L && currentDepth >= depth) {
                continue;
            }

            Collection<Function> neighbors;
            try {
                neighbors = "called".equals(direction)
                    ? current.getCallingFunctions(monitor)
                    : current.getCalledFunctions(monitor);
            } catch (Exception e) {
                printerr("[callgraph] error walking neighbors of " + safeFullName(current)
                    + ": " + e.getMessage());
                continue;
            }
            if (neighbors == null) {
                continue;
            }

            for (Function neighbor : neighbors) {
                if (neighbor == null) {
                    continue;
                }
                String neighborAddr = neighbor.getEntryPoint() != null
                    ? neighbor.getEntryPoint().toString()
                    : "";
                if (neighborAddr.isEmpty()) {
                    continue;
                }
                String fromAddr;
                String toAddr;
                if ("called".equals(direction)) {
                    fromAddr = neighborAddr;
                    toAddr = current.getEntryPoint() != null ? current.getEntryPoint().toString() : "";
                } else {
                    fromAddr = current.getEntryPoint() != null ? current.getEntryPoint().toString() : "";
                    toAddr = neighborAddr;
                }
                String edgeKey = fromAddr + "->" + toAddr;
                if (!edgeKeys.contains(edgeKey)) {
                    edgeKeys.add(edgeKey);
                    Map<String, Object> edge = new LinkedHashMap<>();
                    edge.put("from", fromAddr);
                    edge.put("to", toAddr);
                    edges.add(edge);
                }

                if (!nodesByAddr.containsKey(neighborAddr)) {
                    if ((long) nodesByAddr.size() >= maxNodes) {
                        truncated = true;
                        continue;
                    }
                    nodesByAddr.put(neighborAddr, nodeFor(neighbor));
                    frontier.add(neighbor);
                    frontierDepth.add(currentDepth + 1L);
                }
            }
        }
        return truncated;
    }

    private Map<String, Object> nodeFor(Function func) {
        Map<String, Object> node = new LinkedHashMap<>();
        node.put("address", func.getEntryPoint() != null ? func.getEntryPoint().toString() : "");
        node.put("name", safeName(func));
        return node;
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

    private String renderMermaid(
        List<Map<String, Object>> nodes,
        List<Map<String, Object>> edges,
        String direction
    ) {
        if (nodes.isEmpty()) {
            return "graph LR";
        }
        HashMap<String, String> idByAddr = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        sb.append("graph LR\n");
        int idx = 0;
        for (Map<String, Object> node : nodes) {
            String addr = String.valueOf(node.get("address"));
            String name = String.valueOf(node.get("name"));
            String id = "n" + idx;
            idByAddr.put(addr, id);
            sb.append("  ").append(id).append("[\"").append(escapeMermaid(name)).append("\"]\n");
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

    private String parseDirection(String[] args, int index) {
        if (index >= args.length) {
            return DEFAULT_DIRECTION;
        }
        String raw = args[index];
        if (raw == null || raw.isEmpty()) {
            return DEFAULT_DIRECTION;
        }
        String lc = raw.toLowerCase();
        if ("calling".equals(lc) || "called".equals(lc)) {
            return lc;
        }
        printerr("[callgraph] unknown direction '" + raw + "'; using default " + DEFAULT_DIRECTION);
        return DEFAULT_DIRECTION;
    }

    private long parseLong(String[] args, int index, long fallback) {
        if (index >= args.length) {
            return fallback;
        }
        String raw = args[index];
        if (raw == null || raw.isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            printerr("[callgraph] could not parse '" + raw + "' as long; using default " + fallback);
            return fallback;
        }
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
