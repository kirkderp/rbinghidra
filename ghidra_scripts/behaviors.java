// Whole-binary API call co-occurrence threat pattern detection.
// Usage: <output_path>
// For each non-thunk function, builds the set of APIs it calls, then matches against predefined threat patterns.
// Match condition: at least ceil(pattern.apis.length / 2) APIs match AND at least 2 match.
// Always exits 0 and writes a valid JSON envelope.
// @category rbinghidra

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class behaviors extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.behaviors.v0";
    private static final int MAX_BEHAVIORS = 50;

    private static final int SEV_CRITICAL = 0;
    private static final int SEV_HIGH = 1;
    private static final int SEV_MEDIUM = 2;
    private static final int SEV_LOW = 3;

    private static class ThreatPattern {
        final String id;
        final String name;
        final String severity;
        final String[] apis;
        final String description;

        ThreatPattern(String id, String name, String severity, String[] apis, String description) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.apis = apis;
            this.description = description;
        }
    }

    private static final List<ThreatPattern> PATTERNS = buildPatterns();

    private static List<ThreatPattern> buildPatterns() {
        List<ThreatPattern> p = new ArrayList<>();
        p.add(new ThreatPattern(
            "process_injection_classic",
            "Classic Process Injection",
            "critical",
            new String[]{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
            "Allocates memory in remote process, writes code, creates remote thread"
        ));
        p.add(new ThreatPattern(
            "process_injection_ntapi",
            "NT API Process Injection",
            "critical",
            new String[]{"NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"},
            "Process injection using NT native APIs"
        ));
        p.add(new ThreatPattern(
            "process_hollowing",
            "Process Hollowing",
            "critical",
            new String[]{"CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"},
            "Suspends process, hollows and replaces with payload"
        ));
        p.add(new ThreatPattern(
            "dll_injection",
            "DLL Injection",
            "high",
            new String[]{"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "LoadLibrary"},
            "Injects DLL into remote process"
        ));
        p.add(new ThreatPattern(
            "registry_persistence",
            "Registry Persistence",
            "high",
            new String[]{"RegOpenKey", "RegSetValue"},
            "Modifies registry for persistence"
        ));
        p.add(new ThreatPattern(
            "service_persistence",
            "Service Persistence",
            "high",
            new String[]{"OpenSCManager", "CreateService"},
            "Creates Windows service for persistence"
        ));
        p.add(new ThreatPattern(
            "lsass_access",
            "LSASS Credential Theft",
            "critical",
            new String[]{"OpenProcess", "ReadProcessMemory"},
            "May be reading LSASS memory for credential extraction"
        ));
        p.add(new ThreatPattern(
            "keylogging",
            "Keylogging",
            "high",
            new String[]{"SetWindowsHookEx", "GetAsyncKeyState"},
            "Captures keystrokes"
        ));
        p.add(new ThreatPattern(
            "screen_capture",
            "Screen Capture",
            "medium",
            new String[]{"GetDC", "BitBlt", "CreateCompatibleBitmap"},
            "Captures screen content"
        ));
        p.add(new ThreatPattern(
            "ransomware_pattern",
            "Potential Ransomware",
            "critical",
            new String[]{"FindFirstFile", "FindNextFile", "CryptEncrypt"},
            "File enumeration combined with encryption"
        ));
        p.add(new ThreatPattern(
            "network_c2",
            "Network C2 Communication",
            "medium",
            new String[]{"WSAStartup", "socket", "connect", "send"},
            "Establishes outbound network connection"
        ));
        p.add(new ThreatPattern(
            "defense_evasion",
            "Defense Evasion",
            "high",
            new String[]{"VirtualProtect", "GetProcAddress", "LoadLibrary", "NtSetInformationThread"},
            "Memory permission changes and dynamic loading"
        ));
        return p;
    }

    private static int severityOrder(String severity) {
        if ("critical".equals(severity)) return SEV_CRITICAL;
        if ("high".equals(severity)) return SEV_HIGH;
        if ("medium".equals(severity)) return SEV_MEDIUM;
        return SEV_LOW;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[behaviors] missing args; expected <output_path>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[behaviors] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("total_detected", 0);
        envelope.put("severity_summary", new LinkedHashMap<String, Object>());
        envelope.put("behaviors", new ArrayList<Map<String, Object>>());

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        SymbolTable symTable = currentProgram.getSymbolTable();

        Map<Function, Set<String>> funcApiSets = new HashMap<>();
        FunctionIterator funcIt = fm.getFunctions(true);

        while (funcIt.hasNext()) {
            Function func = funcIt.next();
            if (func == null) {
                continue;
            }
            try {
                if (func.isThunk()) {
                    continue;
                }
            } catch (Exception e) {
                continue;
            }

            Set<String> apiSet = new HashSet<>();
            InstructionIterator instrIt;
            try {
                instrIt = listing.getInstructions(func.getBody(), true);
            } catch (Exception e) {
                printerr("[behaviors] getInstructions failed for " + func.getName() + ": " + e.getMessage());
                continue;
            }

            while (instrIt.hasNext()) {
                Instruction instr;
                try {
                    instr = instrIt.next();
                } catch (Exception e) {
                    printerr("[behaviors] instruction iteration error: " + e.getMessage());
                    break;
                }
                if (instr == null) {
                    continue;
                }
                if (!instr.getFlowType().isCall()) {
                    continue;
                }
                Reference[] refsFrom;
                try {
                    refsFrom = refManager.getReferencesFrom(instr.getAddress());
                } catch (Exception e) {
                    continue;
                }
                for (Reference ref : refsFrom) {
                    if (ref == null) {
                        continue;
                    }
                    if (!ref.getReferenceType().isCall()) {
                        continue;
                    }
                    try {
                        Symbol sym = symTable.getPrimarySymbol(ref.getToAddress());
                        if (sym != null && sym.getName() != null) {
                            apiSet.add(sym.getName());
                        }
                    } catch (Exception e) {
                        printerr("[behaviors] symbol lookup failed: " + e.getMessage());
                    }
                }
            }

            if (!apiSet.isEmpty()) {
                funcApiSets.put(func, apiSet);
            }
        }

        List<Map<String, Object>> detected = new ArrayList<>();

        for (Map.Entry<Function, Set<String>> entry : funcApiSets.entrySet()) {
            Function func = entry.getKey();
            Set<String> apiSet = entry.getValue();
            String funcName;
            try {
                funcName = func.getName();
            } catch (Exception e) {
                funcName = "unknown";
            }
            String funcAddr = func.getEntryPoint() != null ? func.getEntryPoint().toString() : "";

            for (ThreatPattern pattern : PATTERNS) {
                List<String> matchedApis = new ArrayList<>();
                for (String patternApi : pattern.apis) {
                    String patternLc = patternApi.toLowerCase();
                    for (String funcApi : apiSet) {
                        if (funcApi.toLowerCase().contains(patternLc)) {
                            matchedApis.add(funcApi);
                            break;
                        }
                    }
                }
                int matchCount = matchedApis.size();
                int threshold = (int) Math.ceil(pattern.apis.length / 2.0);
                if (matchCount >= threshold && matchCount >= 2) {
                    double confidence = (double) matchCount / pattern.apis.length;
                    confidence = Math.round(confidence * 100.0) / 100.0;

                    Map<String, Object> behavior = new LinkedHashMap<>();
                    behavior.put("pattern_id", pattern.id);
                    behavior.put("pattern_name", pattern.name);
                    behavior.put("severity", pattern.severity);
                    behavior.put("function", funcName);
                    behavior.put("address", funcAddr);
                    behavior.put("confidence", confidence);
                    behavior.put("matched_apis", matchedApis);
                    behavior.put("description", pattern.description);
                    detected.add(behavior);
                }
            }
        }

        Collections.sort(detected, new Comparator<Map<String, Object>>() {
            @Override
            public int compare(Map<String, Object> a, Map<String, Object> b) {
                int sevA = severityOrder((String) a.get("severity"));
                int sevB = severityOrder((String) b.get("severity"));
                if (sevA != sevB) {
                    return Integer.compare(sevA, sevB);
                }
                double confA = (Double) a.get("confidence");
                double confB = (Double) b.get("confidence");
                return Double.compare(confB, confA);
            }
        });

        Map<String, Integer> severitySummary = new LinkedHashMap<>();
        for (Map<String, Object> b : detected) {
            String sev = (String) b.get("severity");
            severitySummary.put(sev, severitySummary.getOrDefault(sev, 0) + 1);
        }

        int total = detected.size();
        boolean truncated = detected.size() > MAX_BEHAVIORS;
        List<Map<String, Object>> output;
        if (truncated) {
            output = new ArrayList<>(detected.subList(0, MAX_BEHAVIORS));
            Map<String, Object> note = new LinkedHashMap<>();
            note.put("note", (detected.size() - MAX_BEHAVIORS) + " additional behaviors truncated");
            output.add(note);
        } else {
            output = detected;
        }

        envelope.put("total_detected", total);
        envelope.put("severity_summary", severitySummary);
        envelope.put("behaviors", output);

        writeOutput(outputPath, envelope);
        println("[behaviors] total_detected=" + total + ", truncated=" + truncated + " -> " + outputPath);
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
