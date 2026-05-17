// Create or update a bookmark at a specific address in the current program.
// Usage: <output_path> <address> [bookmark_type] [category] [comment]
// bookmark_type defaults to "Note" when empty or omitted.
// Always exits 0 and writes a valid envelope; errors populate address_error or bookmark_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class set_bookmark extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.set_bookmark.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("[set_bookmark] missing args; expected <output_path> <address> [bookmark_type] [category] [comment]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String addressStr = args.length >= 2 ? args[1].trim() : "";
        String bookmarkType = (args.length >= 3 && !args[2].trim().isEmpty()) ? args[2].trim() : "Note";
        String category = args.length >= 4 ? args[3] : "";
        String comment = args.length >= 5 ? args[4] : "";

        if (currentProgram == null) {
            printerr("[set_bookmark] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("address", addressStr);
        envelope.put("bookmark_type", bookmarkType);
        envelope.put("category", category);
        envelope.put("comment", comment);
        envelope.put("created_id", -1L);
        envelope.put("address_error", "");
        envelope.put("bookmark_error", "");

        if (addressStr.isEmpty()) {
            envelope.put("address_error", "address must not be empty");
            writeOutput(outputPath, envelope);
            return;
        }

        Address addr = null;
        try {
            AddressFactory af = currentProgram.getAddressFactory();
            String stripped = addressStr;
            if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
                stripped = stripped.substring(2);
            }
            addr = af.getAddress(stripped);
        } catch (Exception e) {
            addr = null;
        }
        if (addr == null) {
            envelope.put("address_error", "Could not parse address: " + addressStr);
            writeOutput(outputPath, envelope);
            return;
        }

        int txId = currentProgram.startTransaction("rbinghidra: set bookmark");
        boolean committed = false;
        try {
            BookmarkManager bmgr = currentProgram.getBookmarkManager();
            Bookmark created = bmgr.setBookmark(addr, bookmarkType, category, comment);
            if (created != null) {
                envelope.put("created_id", created.getId());
            }
            committed = true;
        } catch (Exception e) {
            envelope.put("bookmark_error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        } finally {
            currentProgram.endTransaction(txId, committed);
        }

        writeOutput(outputPath, envelope);
        println("[set_bookmark] addr=" + addressStr + " type=" + bookmarkType + " committed=" + committed);
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
