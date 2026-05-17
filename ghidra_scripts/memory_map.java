// List all memory blocks in the loaded program and write a JSON envelope to the output path.
// Usage: <output_path>
// Always exits 0 and writes a valid envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
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

public class memory_map extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.memory_map.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[memory_map] missing args; expected <output_path>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[memory_map] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        List<Map<String, Object>> blockList = new ArrayList<>();
        for (MemoryBlock block : blocks) {
            Map<String, Object> bm = new LinkedHashMap<>();
            bm.put("name", block.getName());
            bm.put("start", block.getStart().toString());
            bm.put("end", block.getEnd().toString());
            bm.put("size", block.getSize());
            bm.put("readable", block.isRead());
            bm.put("writable", block.isWrite());
            bm.put("executable", block.isExecute());
            bm.put("initialized", block.isInitialized());
            bm.put("is_external", block.isExternalBlock());
            String comment = block.getComment();
            bm.put("comment", comment != null ? comment : "");
            bm.put("type", block.getType().name());
            blockList.add(bm);
        }
        envelope.put("block_count", blockList.size());
        envelope.put("blocks", blockList);

        writeOutput(outputPath, envelope);
        println("[memory_map] wrote " + blockList.size() + " blocks to " + outputPath);
    }

    private void writeOutput(String outputPath, Map<String, Object> envelope) throws IOException {
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
}
