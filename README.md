# rbinghidra

`rbinghidra` is a Model Context Protocol server for Ghidra-backed binary
analysis.

It runs as a stdio MCP server, imports binaries into cached Ghidra projects,
and exposes named tools for decompilation, metadata, graphs, strings, xrefs,
byte reads, and static triage.

The target use case is repeatable Ghidra analysis from an MCP client. Import a
binary by absolute path, wait for analysis to finish, then query the cached
project by SHA-256 cache key, raw SHA-256, or exact program name.

## Requirements

- Ghidra 12.1 or newer
- Java 21 or newer
- Rust 1.88 or newer for building from source
- An MCP client that can run stdio servers

Set `GHIDRA_INSTALL_DIR` to the Ghidra install root, or rely on local discovery.
Use `ghidra_health` from an MCP client to confirm the detected Ghidra path and
version.

## Install

From a local checkout:

```bash
git clone https://github.com/kirkderp/rbinghidra
cd rbinghidra
cargo install --path . --locked
```

From git:

```bash
cargo install --git https://github.com/kirkderp/rbinghidra --locked
```

The installed executable is named `rbinghidra`.

Run it directly:

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1 \
RBM_CACHE_DIR=./rbinghidra-cache \
rbinghidra
```

The process waits for MCP JSON-RPC messages on stdin and writes responses to
stdout.

## MCP Configuration

Example stdio server configuration:

```json
{
  "mcpServers": {
    "rbinghidra": {
      "command": "/absolute/path/to/rbinghidra",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/opt/ghidra_12.1",
        "RBM_CACHE_DIR": "/absolute/path/to/rbinghidra-cache",
        "RBM_GHIDRA_SCRIPTS_DIR": "/absolute/path/to/rbinghidra/ghidra_scripts"
      }
    }
  }
}
```

Use absolute paths for `command`, `RBM_CACHE_DIR`, and
`RBM_GHIDRA_SCRIPTS_DIR`. The scripts directory must point at this repo's
`ghidra_scripts/` directory.

## How It Works

```text
MCP client
  -> stdio JSON-RPC
  -> rbinghidra
  -> Ghidra analyzeHeadless
  -> Java post-script
  -> JSON tool response
```

`ghidra_import` copies the input binary to a staging path, imports it into a
Ghidra project, and caches the project by SHA-256. Later tools run
`analyzeHeadless -process -noanalysis` against the cached project.

Use `ghidra_inventory` to list cached projects. Use `ghidra_delete` to remove
one cached project.

## Example Tool Calls

MCP clients call tools by name. These examples show the tool arguments.

Check Ghidra with `ghidra_health`:

```json
{}
```

Import a binary with `ghidra_import`:

```json
{
  "binary_path": "/absolute/path/to/sample.exe"
}
```

If the result is `running`, call `ghidra_import` again with the same path until
it returns `ready`.

List functions with `ghidra_list_functions`:

```json
{
  "binary_name": "sha256:...",
  "limit": 25
}
```

Decompile a function with `ghidra_decompile`:

```json
{
  "binary_name": "sha256:...",
  "function_address": "140034998"
}
```

Search pseudocode with `ghidra_search_decompilation`:

```json
{
  "binary_name": "sha256:...",
  "query": "FindResource|LoadResource",
  "limit": 5,
  "max_functions": 300
}
```

Read bytes with `ghidra_read_bytes`:

```json
{
  "binary_name": "sha256:...",
  "address": "140034998",
  "size": 32
}
```

Delete cached project data with `ghidra_delete`:

```json
{
  "cache_key": "sha256:..."
}
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `GHIDRA_INSTALL_DIR` | auto-detect | Ghidra install root. |
| `RBM_GHIDRA_SCRIPTS_DIR` | repo `ghidra_scripts/` | Java post-script directory. |
| `RBM_CACHE_DIR` | `./rbinghidra-cache` | Cache root for Ghidra projects and per-call JSON output. |
| `RBM_GHIDRA_TIMEOUT` | `60` | Timeout in seconds for warm-path Ghidra queries. |
| `RBM_GHIDRA_IMPORT_TIMEOUT` | `900` | Timeout in seconds for binary import and analysis. |

## Tool Reference

`rbinghidra` exposes 44 MCP tools.

### Cache And Import

| Tool | Purpose |
| --- | --- |
| `ghidra_health` | Check Ghidra discovery, version, and capability notes. |
| `ghidra_import` | Import and analyze a binary into the SHA-256 project cache. |
| `ghidra_inventory` | List cached binaries, with optional name filtering. |
| `ghidra_cached_metadata` | Read cached program name, path, hash, output path, and function counts. |
| `ghidra_lock_status` | Report active import/query locks for a cached binary. |
| `ghidra_delete` | Delete cached Ghidra project data for one binary. |

### Discovery

| Tool | Purpose |
| --- | --- |
| `ghidra_list_functions` | List functions with filtering and pagination. |
| `ghidra_imports` | List imports with filtering and pagination. |
| `ghidra_exports` | List exports with filtering and pagination. |
| `ghidra_symbols` | Search symbols by name. |
| `ghidra_search_strings` | Search program strings. |
| `ghidra_string_context` | Search strings and return xrefs with decompiler snippets. |
| `ghidra_search_decompilation` | Search decompiled pseudocode across a bounded function set. |

### Metadata

| Tool | Purpose |
| --- | --- |
| `ghidra_memory_map` | Return memory blocks and permissions. |
| `ghidra_defined_data` | List defined data entries. |
| `ghidra_data_types` | List data types. |
| `ghidra_namespaces` | List namespaces. |
| `ghidra_constants` | Scan instruction constants and immediates. |
| `ghidra_equates` | List equates and references. |
| `ghidra_function_stats` | Return size, instruction, block, call, and complexity stats. |
| `ghidra_go_metadata` | Extract heuristic Go build, module, package, and version indicators. |

### Disassembly And Decompiler

| Tool | Purpose |
| --- | --- |
| `ghidra_disassemble` | Disassemble a bounded instruction window at an address. |
| `ghidra_decompile` | Decompile one function to C-like pseudocode. |
| `ghidra_decompile_meta` | Decompile one function with bounded context metadata. |
| `ghidra_decompiler_cfg` | Return decompiler control-flow blocks, edges, calls, memory refs, and optional P-code ops. |
| `ghidra_decompiler_calls` | Summarize internal, external, indirect, and thunk calls. |
| `ghidra_decompiler_memory` | Summarize memory access patterns per decompiler block. |
| `ghidra_decompiler_block_behavior` | Classify behavior by decompiler block. |
| `ghidra_decompiler_slice` | Extract a seed-based decompiler slice. |
| `ghidra_variables` | List function parameters and locals. |
| `ghidra_pcode` | Return P-code for a function. |

### Graphs And Xrefs

| Tool | Purpose |
| --- | --- |
| `ghidra_xrefs` | List xrefs to or from a function or address. |
| `ghidra_callgraph` | Traverse callers or callees with bounded depth and node limits. |
| `ghidra_cfg` | Return a basic-block CFG for one function. |

### Static Triage

| Tool | Purpose |
| --- | --- |
| `ghidra_behaviors` | Scan for behavioral threat patterns with API and string evidence. |
| `ghidra_anti_analysis` | Scan anti-debug, anti-VM, timing, and suspicious-instruction patterns. |
| `ghidra_search_bytes` | Search for a bounded hex byte pattern. |
| `ghidra_function_checkpoints` | Return deferred P-code checkpoints with stack delta data. |
| `ghidra_function_slices` | Return higher-level callsite, field, buffer, indirect, and lineage slices. |
| `ghidra_path_digest` | Summarize calls, constants, markers, buffers, memory writes, and branches over a path. |

### Recovery And Low-Level Inspection

| Tool | Purpose |
| --- | --- |
| `ghidra_read_bytes` | Read bytes at an address with hex and ASCII previews. |
| `ghidra_context_api_slots` | Recover context API slot assignments from an initialization function. |
| `ghidra_thunk_target` | Resolve a thunk target. |
| `ghidra_dynamic_dispatch_table` | Recover dynamic dispatch table entries from seeded context. |

Use `tools/list` from the MCP client for current input schemas.

## Usage Notes

- `binary_path` must be an absolute path.
- `binary_name` accepts `sha256:HEX`, raw SHA-256, or an exact cached program name.
- Function arguments accept names or addresses, depending on the tool.
- Most tools clamp limits before calling Ghidra.
- `ghidra_import` preserves the original binary path in metadata while importing a staged copy.
- `ghidra_delete` removes the cached Ghidra project for one binary.

## Development

Build and test:

```bash
cargo fmt --check
cargo clippy --all-targets --locked --offline
cargo test --locked --offline
```

Compile Ghidra integration tests:

```bash
cargo test --features integration-ghidra --no-run --locked --offline
```

Run ignored tests that require a real Ghidra install:

```bash
cargo test --features integration-ghidra -- --ignored
```

Run from source:

```bash
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1 \
RBM_CACHE_DIR=./rbinghidra-cache \
cargo run --bin rbinghidra
```

## Project Layout

```text
src/             Rust library modules and the rbinghidra binary
tests/           Unit and integration tests
ghidra_scripts/  Java post-scripts run by analyzeHeadless
```

## License

MIT. See [LICENSE](LICENSE).
