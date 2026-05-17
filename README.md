# rbinghidra

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-blue)](rust-toolchain.toml)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.1+-purple)](https://ghidra-sre.org/)

MCP server for Ghidra-based binary analysis.

`rbinghidra` manages per-binary Ghidra projects, imports binaries, and runs 40 Ghidra-backed tools through `analyzeHeadless`. It operates as a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, exposing each query as a named tool.

## Tools

**Project & Cache**
- `ghidra_health` / `ghidra_inventory` / `ghidra_lock_status` / `ghidra_cached_metadata`

**Function Discovery**
- `ghidra_list_functions`  -  function inventory with name filtering
- `ghidra_imports` / `ghidra_exports` / `ghidra_symbols`  -  import/export/symbol tables
- `ghidra_namespaces` / `ghidra_data_types` / `ghidra_search_strings` / `ghidra_memory_map` / `ghidra_defined_data`
- `ghidra_function_stats`  -  cyclomatic complexity, instruction count, basic-block count, call count
- `ghidra_equates`  -  named constants

**Decompilation**
- `ghidra_decompile`  -  C-like pseudocode with configurable simplification style
- `ghidra_decompile_meta`  -  decompilation with adjacent function context
- `ghidra_decompiler_calls`  -  external/internal call analysis
- `ghidra_decompiler_cfg`  -  decompiler-level control flow graph with block summaries
- `ghidra_decompiler_memory`  -  memory access patterns per decompiler block
- `ghidra_decompiler_block_behavior`  -  behavior classification per decompiler block
- `ghidra_decompiler_slice`  -  seed-based decompiler slice extraction
- `ghidra_function_slices`  -  higher-level callsite, field, buffer, indirect, and lineage slices
- `ghidra_path_digest`  -  compact block/event digest for a function path
- `ghidra_variables`  -  function parameter and local listings
- `ghidra_pcode`  -  P-code extraction

**Analysis**
- `ghidra_behaviors`  -  behavioral threat pattern scanning with API and string evidence
- `ghidra_anti_analysis`  -  anti-debug, anti-VM, timing check, PEB access detection
- `ghidra_function_checkpoints`  -  deferred P-code checkpoints with stack delta analysis

**Navigation & CFG**
- `ghidra_callgraph`  -  callgraph traversal with configurable depth and node limits
- `ghidra_cfg`  -  basic-block control flow graph
- `ghidra_xrefs`  -  cross-references to or from a function/address

**Search & Recovery**
- `ghidra_search_bytes`  -  hex pattern search
- `ghidra_disassemble`
- `ghidra_context_api_slots` / `ghidra_thunk_target` / `ghidra_dynamic_dispatch_table`
- `ghidra_read_bytes`

**Import & Cleanup**
- `ghidra_import`  -  import a binary with optional loader/processor/cspec options
- `ghidra_delete`  -  delete cached Ghidra project data for a binary

## Requirements

- **Ghidra 12.1+**, discoverable via `GHIDRA_INSTALL_DIR`
- **Java 21+** (Ghidra launch scripts)
- **Rust stable** toolchain
- Java scripts in `ghidra_scripts/` are pre-compiled to `.class` files alongside source (required by Ghidra 12.1 headless).

## Quick Start

```bash
cargo build --workspace
cargo test --workspace

# Run the MCP server
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1 \
  RBM_CACHE_DIR=./cache \
  cargo run -p rbm-server
```

The server speaks the MCP protocol over stdio. Configure your MCP client to use it as a stdio subprocess:

```json
{
  "mcpServers": {
    "rbinghidra": {
      "command": "/path/to/rbinghidra",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_12.1"
      }
    }
  }
}
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `GHIDRA_INSTALL_DIR` | (auto-detect) | Ghidra install root |
| `RBM_CACHE_DIR` | `./rbinghidra-cache` | Cache root (relative CWD) |
| `RBM_GHIDRA_TIMEOUT` | 60 | Per-call timeout (seconds) |
| `RBM_GHIDRA_IMPORT_TIMEOUT` | 900 | Import timeout (seconds) |

## Architecture

```
MCP Client
  -> stdio JSON-RPC
  -> rbinghidra server
  -> Ghidra analyzeHeadless
     (cold path: import per SHA-256)
     (warm path: -process -noanalysis for cached projects)
  -> JSON results
```

Projects are imported once and cached per SHA-256. Subsequent queries use warm-path calls that skip re-analysis, enabling sub-second response times for most operations.

## Project Structure

```
crates/
  rbm-core/      Cache paths, config, environment, error types
  rbm-ghidra/    Ghidra project management, import, and query modules
  rbm-server/    MCP server binary (rbinghidra)
ghidra_scripts/  Java post-scripts executed by analyzeHeadless
```

## License

MIT  -  see [LICENSE](LICENSE).
