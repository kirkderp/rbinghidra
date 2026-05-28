import re

with open("crates/rbm-ghidra/tests/context_api_slots_unit.rs", "r") as f:
    content = f.read()

content = content.replace(
    '''    let mock_script = format!(
        r#"#!/bin/bash
# Mock analyzeHeadless to write JSON to the expected output path
for i in "$@"; do
    if [[ $i == *".json" ]]; then
        echo '{}' > "$i"
    fi
done
"#,
        json_output
    );''',
    '''    let mock_script = format!(
        r#"#!/bin/bash
# Mock analyzeHeadless to write JSON to the expected output path
for i in "$@"; do
    if [[ $i == *".json" ]]; then
        echo '{json_output}' > "$i"
    fi
done
"#
    );'''
)


with open("crates/rbm-ghidra/tests/context_api_slots_unit.rs", "w") as f:
    f.write(content)
