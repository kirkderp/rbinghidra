// Set a comment at an address and write a JSON envelope to the output path.
// Usage: <output_path> <address> <comment> [comment_type]
// comment_type is one of: PLATE, PRE, EOL, POST, REPEATABLE (default: PLATE).
// Passing an empty comment string clears the comment at that address.
// Always exits 0 and writes a valid envelope; errors populate address_error or comment_error.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CodeUnit;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

public class set_comment extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.set_comment.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("[set_comment] missing args; expected <output_path> <address> <comment> [comment_type]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String addressArg = args[1];
        String comment = args[2];
        String commentTypeArg = args.length >= 4 && args[3] != null && !args[3].isEmpty()
            ? args[3]
            : "PLATE";

        if (currentProgram == null) {
            printerr("[set_comment] no program loaded");
            throw new IllegalStateException("no program");
        }

        int commentTypeCode;
        switch (commentTypeArg.toUpperCase()) {
            case "PRE":        commentTypeCode = CodeUnit.PRE_COMMENT;        commentTypeArg = "PRE";        break;
            case "EOL":        commentTypeCode = CodeUnit.EOL_COMMENT;        commentTypeArg = "EOL";        break;
            case "POST":       commentTypeCode = CodeUnit.POST_COMMENT;       commentTypeArg = "POST";       break;
            case "REPEATABLE": commentTypeCode = CodeUnit.REPEATABLE_COMMENT; commentTypeArg = "REPEATABLE"; break;
            default:           commentTypeCode = CodeUnit.PLATE_COMMENT;      commentTypeArg = "PLATE";      break;
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("address", addressArg);
        envelope.put("comment_type", commentTypeArg);
        envelope.put("comment", comment);
        envelope.put("address_error", "");
        envelope.put("comment_error", "");

        AddressFactory af = currentProgram.getAddressFactory();
        String stripped = addressArg;
        if (stripped.startsWith("0x") || stripped.startsWith("0X")) {
            stripped = stripped.substring(2);
        }
        Address addr;
        try {
            addr = af.getAddress(stripped);
        } catch (Exception e) {
            envelope.put("address_error", "cannot parse address: " + addressArg);
            writeOutput(outputPath, envelope);
            println("[set_comment] cannot parse address: " + addressArg);
            return;
        }
        if (addr == null) {
            envelope.put("address_error", "cannot parse address: " + addressArg);
            writeOutput(outputPath, envelope);
            println("[set_comment] cannot parse address: " + addressArg);
            return;
        }

        // setComment with null or empty string clears; pass null only when empty to be explicit.
        String commentToSet = comment.isEmpty() ? null : comment;

        int txId = currentProgram.startTransaction("rbinghidra: set comment");
        boolean committed = false;
        try {
            currentProgram.getListing().setComment(addr, commentTypeCode, commentToSet);
            committed = true;
        } catch (Exception e) {
            envelope.put("comment_error", e.getMessage() != null ? e.getMessage() : e.getClass().getName());
        } finally {
            currentProgram.endTransaction(txId, committed);
        }

        writeOutput(outputPath, envelope);
        println("[set_comment] " + commentTypeArg + " comment at " + addressArg
            + " committed=" + committed);
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
