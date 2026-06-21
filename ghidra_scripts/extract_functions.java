// Extract the function list and write a JSON summary to the path passed as the first script argument.
// The optional second script argument is the caller-visible binary path used in metadata.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class extract_functions extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.extract_functions.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[extract_functions] missing required argument <output_path>");
            throw new IllegalArgumentException("missing output path");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[extract_functions] no program loaded");
            throw new IllegalStateException("no program");
        }
        String programPath = currentProgram.getExecutablePath();
        if (args.length > 1 && !args[1].trim().isEmpty()) {
            programPath = args[1];
        }

        List<Map<String, Object>> functions = new ArrayList<>();
        int errorCount = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function fn = it.next();
            try {
                functions.add(functionToMap(fn));
            } catch (Exception e) {
                errorCount++;
                printerr("[extract_functions] error on function " + fn.getName() + ": " + e.getMessage());
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema", SCHEMA);
        result.put("program_name", currentProgram.getName());
        result.put("program_path", programPath);
        result.put("function_count", functions.size());
        result.put("error_count", errorCount);
        result.put("functions", functions);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = gson.toJson(result);
        writeOutput(outputPath, json);

        println("[extract_functions] wrote " + functions.size() + " functions ("
            + errorCount + " errors) to " + outputPath);
    }

    private Map<String, Object> functionToMap(Function fn) {
        AddressSetView body = fn.getBody();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", fn.getName());
        entry.put("entry", fn.getEntryPoint().toString());
        entry.put("size", body.getNumAddresses());
        entry.put("is_thunk", fn.isThunk());
        entry.put("is_external", fn.isExternal());
        String cc = fn.getCallingConventionName();
        entry.put("calling_convention", cc != null ? cc : "unknown");
        entry.put("signature", fn.getSignature().getPrototypeString());
        return entry;
    }

    private void writeOutput(String outputPath, String json) throws IOException {
        Path path = Paths.get(outputPath);
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path tmp = path.resolveSibling(path.getFileName().toString() + ".tmp");
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(tmp, StandardCharsets.UTF_8))) {
            pw.write(json);
        }
        try {
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicMoveError) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
