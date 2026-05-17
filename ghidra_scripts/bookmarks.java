// List bookmarks/annotations in the current program, with optional type filter.
// Usage: <output_path> [type_filter]
// type_filter is optional; empty string returns all bookmark types.
// Always exits 0 and writes a valid envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class bookmarks extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.bookmarks.v0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[bookmarks] missing args; expected <output_path> [type_filter]");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];
        String typeFilter = args.length >= 2 ? args[1].trim() : "";

        if (currentProgram == null) {
            printerr("[bookmarks] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("type_filter", typeFilter);
        envelope.put("total_matched", 0);
        envelope.put("bookmarks", new ArrayList<>());

        BookmarkManager bmgr = currentProgram.getBookmarkManager();
        List<Map<String, Object>> bookmarkList = new ArrayList<>();
        Iterator<Bookmark> it;
        if (!typeFilter.isEmpty()) {
            it = bmgr.getBookmarksIterator(typeFilter);
        } else {
            it = bmgr.getBookmarksIterator();
        }
        while (it.hasNext()) {
            Bookmark b = it.next();
            Map<String, Object> bmap = new LinkedHashMap<>();
            bmap.put("id", b.getId());
            bmap.put("address", b.getAddress().toString());
            bmap.put("type", b.getTypeString());
            String cat = b.getCategory();
            bmap.put("category", cat != null ? cat : "");
            String comment = b.getComment();
            bmap.put("comment", comment != null ? comment : "");
            bookmarkList.add(bmap);
        }

        envelope.put("type_filter", typeFilter);
        envelope.put("total_matched", bookmarkList.size());
        envelope.put("bookmarks", bookmarkList);

        writeOutput(outputPath, envelope);
        println("[bookmarks] type_filter='" + typeFilter + "' total=" + bookmarkList.size());
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
