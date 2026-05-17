// Whole-binary scan for anti-analysis evidence: anti-debug/anti-VM API calls, suspicious instructions, and PEB/TEB access.
// Usage: <output_path>
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class anti_analysis extends GhidraScript {

    private static final String SCHEMA = "rbm.ghidra.anti_analysis.v0";
    private static final int MAX_FINDINGS = 200;

    private static final Map<String, String[]> CATEGORY_APIS = buildCategoryApis();
    private static final Map<String, String> CATEGORY_SEVERITY = buildCategorySeverity();
    private static final Set<String> SUSPICIOUS_MNEMONICS = buildSuspiciousMnemonics();

    private static Map<String, String[]> buildCategoryApis() {
        Map<String, String[]> m = new LinkedHashMap<>();
        m.put("debugger_detection", new String[]{
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "DebugActiveProcess"
        });
        m.put("timing_checks", new String[]{
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
            "GetSystemTimeAsFileTime", "timeGetTime"
        });
        m.put("process_enumeration", new String[]{
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "EnumProcesses", "NtQuerySystemInformation"
        });
        m.put("vm_detection", new String[]{
            "GetSystemFirmwareTable", "EnumSystemFirmwareTable", "WMI", "SMBIOS"
        });
        m.put("exception_based", new String[]{
            "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
            "RtlAddVectoredExceptionHandler"
        });
        m.put("memory_checks", new String[]{
            "VirtualQuery", "NtQueryVirtualMemory", "ReadProcessMemory"
        });
        return m;
    }

    private static Map<String, String> buildCategorySeverity() {
        Map<String, String> m = new HashMap<>();
        m.put("debugger_detection", "high");
        m.put("timing_checks", "medium");
        m.put("process_enumeration", "medium");
        m.put("vm_detection", "high");
        m.put("exception_based", "medium");
        m.put("memory_checks", "medium");
        return m;
    }

    private static Set<String> buildSuspiciousMnemonics() {
        Set<String> s = new HashSet<>(Arrays.asList(
            "RDTSC", "CPUID", "INT3", "SIDT", "SGDT", "SLDT", "STR"
        ));
        return s;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("[anti_analysis] missing args; expected <output_path>");
            throw new IllegalArgumentException("missing args");
        }
        String outputPath = args[0];

        if (currentProgram == null) {
            printerr("[anti_analysis] no program loaded");
            throw new IllegalStateException("no program");
        }

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("schema", SCHEMA);
        envelope.put("total_findings", 0);
        envelope.put("summary", new LinkedHashMap<String, Object>());
        envelope.put("findings", new ArrayList<Map<String, Object>>());

        List<Map<String, Object>> findings = new ArrayList<>();

        scanApiCalls(findings);
        scanInstructions(findings);

        Map<String, Integer> byCategory = new LinkedHashMap<>();
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (Map<String, Object> f : findings) {
            String cat = (String) f.get("category");
            String sev = (String) f.get("severity");
            byCategory.put(cat, byCategory.getOrDefault(cat, 0) + 1);
            bySeverity.put(sev, bySeverity.getOrDefault(sev, 0) + 1);
        }

        int total = findings.size();
        boolean truncated = findings.size() > MAX_FINDINGS;
        List<Map<String, Object>> output;
        if (truncated) {
            output = new ArrayList<>(findings.subList(0, MAX_FINDINGS));
            Map<String, Object> note = new LinkedHashMap<>();
            note.put("note", (findings.size() - MAX_FINDINGS) + " additional findings truncated");
            output.add(note);
        } else {
            output = findings;
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("by_category", byCategory);
        summary.put("by_severity", bySeverity);

        envelope.put("total_findings", total);
        envelope.put("summary", summary);
        envelope.put("findings", output);

        writeOutput(outputPath, envelope);
        println("[anti_analysis] total_findings=" + total + ", truncated=" + truncated + " -> " + outputPath);
    }

    private void scanApiCalls(List<Map<String, Object>> findings) {
        SymbolTable symTable = currentProgram.getSymbolTable();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        for (Map.Entry<String, String[]> entry : CATEGORY_APIS.entrySet()) {
            String category = entry.getKey();
            String severity = CATEGORY_SEVERITY.getOrDefault(category, "medium");
            for (String apiName : entry.getValue()) {
                SymbolIterator symIt;
                try {
                    symIt = symTable.getSymbols(apiName);
                } catch (Exception e) {
                    printerr("[anti_analysis] symbol lookup failed for " + apiName + ": " + e.getMessage());
                    continue;
                }
                while (symIt.hasNext()) {
                    Symbol sym = symIt.next();
                    if (sym == null) {
                        continue;
                    }
                    ReferenceIterator refs;
                    try {
                        refs = refManager.getReferencesTo(sym.getAddress());
                    } catch (Exception e) {
                        printerr("[anti_analysis] getReferencesTo failed for " + apiName + ": " + e.getMessage());
                        continue;
                    }
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (ref == null) {
                            continue;
                        }
                        if (!ref.getReferenceType().isCall()) {
                            continue;
                        }
                        String callerAddr = ref.getFromAddress() != null
                            ? ref.getFromAddress().toString() : "";
                        String funcName = "unknown";
                        try {
                            Function callingFunc = fm.getFunctionContaining(ref.getFromAddress());
                            if (callingFunc != null) {
                                funcName = callingFunc.getName();
                            }
                        } catch (Exception e) {
                            funcName = "unknown";
                        }
                        Map<String, Object> finding = new LinkedHashMap<>();
                        finding.put("category", category);
                        finding.put("technique", apiName);
                        finding.put("address", callerAddr);
                        finding.put("function", funcName);
                        finding.put("severity", severity);
                        findings.add(finding);
                    }
                }
            }
        }
    }

    private void scanInstructions(List<Map<String, Object>> findings) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        FunctionIterator funcIt = fm.getFunctions(true);
        Set<String> pebSeenFunctions = new HashSet<>();

        while (funcIt.hasNext()) {
            Function func = funcIt.next();
            if (func == null) {
                continue;
            }
            String funcName;
            try {
                funcName = func.getName();
            } catch (Exception e) {
                funcName = "unknown";
            }

            InstructionIterator instrIt;
            try {
                instrIt = listing.getInstructions(func.getBody(), true);
            } catch (Exception e) {
                printerr("[anti_analysis] getInstructions failed for " + funcName + ": " + e.getMessage());
                continue;
            }

            while (instrIt.hasNext()) {
                Instruction instr;
                try {
                    instr = instrIt.next();
                } catch (Exception e) {
                    printerr("[anti_analysis] instruction iteration error in " + funcName + ": " + e.getMessage());
                    break;
                }
                if (instr == null) {
                    continue;
                }

                String mnemonic = instr.getMnemonicString().toUpperCase();
                String instrStr = instr.toString();
                String instrUpper = instrStr.toUpperCase();
                String addr = instr.getAddress() != null ? instr.getAddress().toString() : "";

                if (SUSPICIOUS_MNEMONICS.contains(mnemonic)) {
                    if (mnemonic.equals("INT")) {
                        if (!instrUpper.contains("0X2D") && !instrUpper.contains("0X03")) {
                            continue;
                        }
                    }
                    Map<String, Object> finding = new LinkedHashMap<>();
                    finding.put("category", "suspicious_instruction");
                    finding.put("technique", mnemonic);
                    finding.put("address", addr);
                    finding.put("function", funcName);
                    finding.put("severity", "medium");
                    finding.put("instruction", instrStr);
                    findings.add(finding);
                }

                if (instrUpper.contains("FS:") && (instrUpper.contains("0X30") || instrUpper.contains("0X18"))) {
                    if (!pebSeenFunctions.contains(funcName)) {
                        pebSeenFunctions.add(funcName);
                        Map<String, Object> finding = new LinkedHashMap<>();
                        finding.put("category", "peb_teb_access");
                        finding.put("technique", "Direct PEB/TEB access");
                        finding.put("address", addr);
                        finding.put("function", funcName);
                        finding.put("severity", "high");
                        finding.put("instruction", instrStr);
                        findings.add(finding);
                    }
                }
            }
        }
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
