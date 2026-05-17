// List cross-references to or from a symbol/address and write a JSON envelope to the path passed as the first script argument.
// Usage: <output_path> <name_or_address> [offset] [limit] [direction]
// name_or_address is parsed as an address first; on failure it falls back to case-insensitive exact-then-partial match against the fully-qualified symbol name.
// direction is "to" (default) or "from".
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class list_xrefs extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.list_xrefs.v0";
    private static final long DEFAULT_OFFSET = 0L;
    private static final long DEFAULT_LIMIT = 25L;
    private static final long MAX_LIMIT = 1000L;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[list_xrefs] missing args; expected <output_path> <name_or_address> [offset] [limit] [direction]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];
        long offset = parseLong(args, 2, DEFAULT_OFFSET);
        long limit = parseLong(args, 3, DEFAULT_LIMIT);
        String direction = parseDirection(args, 4);
        if (offset < 0L) {
            offset = 0L;
        }
        if (limit < 0L) {
            limit = 0L;
        }
        if (limit > MAX_LIMIT) {
            limit = MAX_LIMIT;
        }

        if (currentProgram == null) {
            printerr("[list_xrefs] no program loaded");
            throw new IllegalStateException("no program");
        }

        Address targetAddress = null;
        String resolvedSymbolName = "";
        String resolutionError = "";

        try {
            String stripped = nameOrAddress;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            targetAddress = currentProgram.getAddressFactory().getAddress(stripped);
        } catch (Exception e) {
            targetAddress = null;
        }

        SymbolTable table = currentProgram.getSymbolTable();
        if (targetAddress != null) {
            Symbol primary = table.getPrimarySymbol(targetAddress);
            if (primary != null) {
                try {
                    resolvedSymbolName = primary.getName(true);
                } catch (Exception e) {
                    resolvedSymbolName = primary.getName();
                }
            }
        } else {
            String nameLc = nameOrAddress.toLowerCase();
            List<Symbol> exactMatches = new ArrayList<>();
            List<Symbol> simpleExactMatches = new ArrayList<>();
            List<Symbol> partialMatches = new ArrayList<>();
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol sym = it.next();
                if (sym == null) {
                    continue;
                }
                String qualified;
                try {
                    qualified = sym.getName(true);
                } catch (Exception e) {
                    continue;
                }
                if (qualified == null) {
                    continue;
                }
                String qLc = qualified.toLowerCase();
                if (nameLc.equals(qLc)) {
                    exactMatches.add(sym);
                    continue;
                }
                String simple = sym.getName();
                if (simple != null && nameLc.equals(simple.toLowerCase())) {
                    simpleExactMatches.add(sym);
                } else if (qLc.contains(nameLc)) {
                    partialMatches.add(sym);
                }
            }

            List<Symbol> picked = !exactMatches.isEmpty()
                ? exactMatches
                : (!simpleExactMatches.isEmpty() ? simpleExactMatches : partialMatches);
            picked = preferSingleExternalSymbol(picked);
            if (picked.isEmpty()) {
                resolutionError = "Symbol '" + nameOrAddress + "' not found.";
            } else if (picked.size() > 1) {
                StringBuilder sb = new StringBuilder();
                sb.append("Ambiguous match for '").append(nameOrAddress).append("'. Matches: ");
                int shown = 0;
                for (Symbol s : picked) {
                    if (shown > 0) {
                        sb.append(", ");
                    }
                    try {
                        sb.append(s.getName(true));
                    } catch (Exception e) {
                        sb.append("?");
                    }
                    if (s.getAddress() != null) {
                        sb.append(" @ ").append(s.getAddress().toString());
                    }
                    shown++;
                    if (shown >= 5 && picked.size() > shown) {
                        sb.append(" (+").append(picked.size() - shown).append(" more)");
                        break;
                    }
                }
                resolutionError = sb.toString();
            } else {
                Symbol s = picked.get(0);
                targetAddress = s.getAddress();
                try {
                    resolvedSymbolName = s.getName(true);
                } catch (Exception e) {
                    resolvedSymbolName = s.getName();
                }
            }
        }

        long totalMatched = 0L;
        long errorCount = 0L;
        List<Map<String, Object>> page = new ArrayList<>();

        if (resolutionError.isEmpty() && targetAddress != null) {
            ReferenceManager rm = currentProgram.getReferenceManager();
            FunctionManager fm = currentProgram.getFunctionManager();
            Iterable<Reference> refs = referencesFor(rm, fm, targetAddress, direction);
            for (Reference ref : refs) {
                try {
                    if (ref == null) {
                        continue;
                    }
                    long index = totalMatched;
                    totalMatched++;
                    if (index < offset) {
                        continue;
                    }
                    if ((long) page.size() >= limit) {
                        continue;
                    }
                    page.add(refToMap(ref, fm));
                } catch (Exception e) {
                    errorCount++;
                    printerr("[list_xrefs] error on reference: " + e.getMessage());
                }
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("direction", direction);
        envelope.put(
            "resolved_address",
            targetAddress != null && resolutionError.isEmpty() ? targetAddress.toString() : ""
        );
        envelope.put("resolved_symbol_name", resolvedSymbolName);
        envelope.put("resolution_error", resolutionError);
        envelope.put("offset", offset);
        envelope.put("limit", limit);
        envelope.put("total_matched", totalMatched);
        envelope.put("error_count", errorCount);
        envelope.put("xrefs", page);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        writeOutput(outputPath, json);
        if (!resolutionError.isEmpty()) {
            println("[list_xrefs] resolution failed for '" + nameOrAddress + "': " + resolutionError);
        } else {
            println("[list_xrefs] matched " + totalMatched + " xrefs " + direction + " '" + nameOrAddress
                + "' (resolved to " + (targetAddress != null ? targetAddress.toString() : "?")
                + "), returning " + page.size() + " (offset=" + offset + ", limit=" + limit + ") to " + outputPath);
        }
    }

    private List<Symbol> preferSingleExternalSymbol(List<Symbol> symbols) {
        if (symbols.size() <= 1) {
            return symbols;
        }
        List<Symbol> external = new ArrayList<>();
        for (Symbol sym : symbols) {
            try {
                if (sym.isExternal()) {
                    external.add(sym);
                }
            } catch (Exception e) {
            }
        }
        return external.size() == 1 ? external : symbols;
    }

    private Iterable<Reference> referencesFor(
        ReferenceManager rm,
        FunctionManager fm,
        Address targetAddress,
        String direction
    ) {
        List<Reference> refs = new ArrayList<>();
        if ("from".equals(direction)) {
            Function functionAt = fm.getFunctionAt(targetAddress);
            if (functionAt != null && functionAt.getBody() != null) {
                InstructionIterator instructions =
                    currentProgram.getListing().getInstructions(functionAt.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    if (instruction == null || instruction.getAddress() == null) {
                        continue;
                    }
                    for (Reference ref : rm.getReferencesFrom(instruction.getAddress())) {
                        refs.add(ref);
                    }
                }
                return refs;
            }
            for (Reference ref : rm.getReferencesFrom(targetAddress)) {
                refs.add(ref);
            }
            return refs;
        }
        ReferenceIterator it = rm.getReferencesTo(targetAddress);
        while (it.hasNext()) {
            refs.add(it.next());
        }
        return refs;
    }

    private Map<String, Object> refToMap(Reference ref, FunctionManager fm) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put(
            "from_address",
            ref.getFromAddress() != null ? ref.getFromAddress().toString() : ""
        );
        entry.put(
            "to_address",
            ref.getToAddress() != null ? ref.getToAddress().toString() : ""
        );
        entry.put(
            "ref_type",
            ref.getReferenceType() != null ? ref.getReferenceType().toString() : ""
        );
        String functionName = "";
        try {
            if (ref.getFromAddress() != null) {
                Function containing = fm.getFunctionContaining(ref.getFromAddress());
                if (containing != null) {
                    functionName = containing.getName();
                }
            }
        } catch (Exception e) {
            // leave empty
        }
        entry.put("function_name", functionName);
        return entry;
    }

    private long parseLong(String[] args, int index, long defaultValue) {
        if (index >= args.length) {
            return defaultValue;
        }
        String raw = args[index];
        if (raw == null || raw.isEmpty()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            printerr("[list_xrefs] could not parse '" + raw + "' as long; using default " + defaultValue);
            return defaultValue;
        }
    }

    private String parseDirection(String[] args, int index) {
        if (index >= args.length) {
            return "to";
        }
        String raw = args[index];
        if (raw == null || raw.trim().isEmpty()) {
            return "to";
        }
        String value = raw.trim().toLowerCase();
        if ("from".equals(value)) {
            return "from";
        }
        return "to";
    }

    private void writeOutput(String outputPath, String json) throws IOException {
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            pw.write(json);
        }
    }
}
