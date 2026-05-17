// Compute function statistics: cyclomatic complexity, instruction count, call count, basic block count.
// Usage: <output_path> <name_or_address>
// name_or_address is parsed as an address first; on failure falls back to case-insensitive exact-then-partial match.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.util.task.TaskMonitor;
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

public class function_stats extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.function_stats.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[function_stats] missing args; expected <output_path> <name_or_address>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String nameOrAddress = args[1];

        if (currentProgram == null) {
            printerr("[function_stats] no program loaded");
            throw new IllegalStateException("no program");
        }

        Address targetAddress = null;
        String resolvedSymbolName = "";
        String resolutionError = "";

        // Try as address first
        try {
            String stripped = nameOrAddress;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            targetAddress = currentProgram.getAddressFactory().getAddress(stripped);
        } catch (Exception e) {
            targetAddress = null;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function targetFunction = null;

        if (targetAddress != null) {
            targetFunction = fm.getFunctionContaining(targetAddress);
            if (targetFunction == null) {
                targetFunction = fm.getFunctionAt(targetAddress);
            }
            if (targetFunction != null) {
                try {
                    resolvedSymbolName = targetFunction.getName(true);
                } catch (Exception e) {
                    resolvedSymbolName = targetFunction.getName();
                }
            } else {
                resolutionError = "No function found at address '" + nameOrAddress + "'";
            }
        } else {
            // Fall back to symbol search
            SymbolTable table = currentProgram.getSymbolTable();
            String nameLc = nameOrAddress.toLowerCase();
            List<Symbol> matches = new ArrayList<>();
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol sym = it.next();
                if (sym == null || sym.getSymbolType() == null) continue;
                if (!sym.getSymbolType().toString().contains("Function")) continue;
                String qualified;
                try { qualified = sym.getName(true); } catch (Exception e) { continue; }
                if (qualified == null) continue;
                if (qualified.toLowerCase().equals(nameLc)) {
                    matches.add(sym);
                } else if (qualified.toLowerCase().contains(nameLc)) {
                    matches.add(sym);
                }
            }
            if (!matches.isEmpty()) {
                Symbol s = matches.get(0);
                targetAddress = s.getAddress();
                try { resolvedSymbolName = s.getName(true); } catch (Exception e) { resolvedSymbolName = s.getName(); }
                targetFunction = fm.getFunctionAt(targetAddress);
                if (targetFunction == null) targetFunction = fm.getFunctionContaining(targetAddress);
            } else {
                resolutionError = "Symbol '" + nameOrAddress + "' not found.";
            }
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("query", nameOrAddress);
        envelope.put("resolved_address", targetAddress != null ? targetAddress.toString() : "");
        envelope.put("resolved_symbol_name", resolvedSymbolName);
        envelope.put("resolution_error", resolutionError);

        if (targetFunction != null && resolutionError.isEmpty()) {
            // Basic stats
            long totalInstructions = 0;
            long totalCalls = 0;
            long totalMemoryRefs = 0;
            Map<String, Long> importsByLib = new LinkedHashMap<>();
            ReferenceManager rm = currentProgram.getReferenceManager();

            InstructionIterator instIt = currentProgram.getListing().getInstructions(targetFunction.getBody(), true);
            while (instIt.hasNext()) {
                Instruction inst = instIt.next();
                if (inst == null) continue;
                totalInstructions++;
                if (inst.getFlowType().isCall()) {
                    totalCalls++;
                }
                for (Reference ref : rm.getReferencesFrom(inst.getAddress())) {
                    if (ref != null) {
                        totalMemoryRefs++;
                        if (ref.isExternalReference()) {
                        // External refs: look up via external manager
                        String libName = "";
                        try {
                            ghidra.program.model.symbol.ExternalManager extMgr =
                                currentProgram.getExternalManager();
                            ghidra.program.model.symbol.Symbol refSym = null;
                            try {
                                ghidra.program.model.symbol.SymbolTable symTable =
                                    currentProgram.getSymbolTable();
                                refSym = symTable.getPrimarySymbol(ref.getToAddress());
                            } catch (Exception ex) { /* fall through */ }
                            ghidra.program.model.symbol.ExternalLocation extLoc = null;
                            if (refSym != null) {
                                extLoc = extMgr.getExternalLocation(refSym);
                            }
                            if (extLoc != null && extLoc.getLibraryName() != null) {
                                libName = extLoc.getLibraryName();
                            }
                        } catch (Exception ex) {
                            libName = "?";
                        }
                        importsByLib.merge(libName, 1L, Long::sum);
                    }
                    }
                }
            }

            // Basic block count via BasicBlockModel
            BasicBlockModel bbm = new BasicBlockModel(currentProgram);
            CodeBlockIterator bbIt = bbm.getCodeBlocksContaining(targetFunction.getBody(), TaskMonitor.DUMMY);
            long totalBlocks = 0;
            while (bbIt.hasNext()) { bbIt.next(); totalBlocks++; }

            // Cyclomatic complexity: E - N + 2 for connected graph
            // For simplicity: blocks + calls (approximate)
            long cyclomaticComplexity = totalBlocks > 0 ? totalBlocks + totalCalls - 1L : 1L;
            if (cyclomaticComplexity < 1) cyclomaticComplexity = 1;

            long functionSize = functionBodyByteSize(targetFunction);
            long externalCallCount = 0;
            for (Long count : importsByLib.values()) {
                if (count != null) {
                    externalCallCount += count.longValue();
                }
            }

            envelope.put("function_name", resolvedSymbolName);
            envelope.put("address", targetAddress.toString());
            envelope.put("signature", targetFunction.getSignature().getPrototypeString());
            envelope.put("size_bytes", functionSize);
            envelope.put("instruction_count", totalInstructions);
            envelope.put("basic_block_count", totalBlocks);
            envelope.put("cyclomatic_complexity", cyclomaticComplexity);
            envelope.put("call_count", totalCalls);
            envelope.put("external_call_count", externalCallCount);
            envelope.put("memory_reference_count", totalMemoryRefs);
            envelope.put("imports_by_library", importsByLib);
            envelope.put("has_stack_frame", targetFunction.hasCustomVariableStorage());
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(envelope);
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8))) {
            pw.write(json);
        }
        if (!resolutionError.isEmpty()) {
            println("[function_stats] resolution failed: " + resolutionError);
        } else {
            println("[function_stats] computed stats for '" + resolvedSymbolName + "'");
        }
    }

    private long functionBodyByteSize(Function fn) {
        long size = 0L;
        try {
            for (AddressRange range : fn.getBody().getAddressRanges()) {
                if (range != null) {
                    size += range.getMaxAddress().subtract(range.getMinAddress()) + 1L;
                }
            }
        } catch (Exception e) {
            try {
                return fn.getBody().getMaxAddress().subtract(fn.getBody().getMinAddress()) + 1L;
            } catch (Exception ignored) {
                return 0L;
            }
        }
        return size;
    }
}
