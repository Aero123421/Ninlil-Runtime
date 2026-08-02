#!/usr/bin/env python3
"""ESP-IDF packaging + M3-basic + owner/cell + durable-storage authority gate."""

from __future__ import annotations

import hashlib
import pathlib
import re
import shlex
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PORTABLE_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_runtime_private_sources.cmake"
PORT_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_esp_idf_port_sources.cmake"
STORAGE_AUTHORITY = REPO_ROOT / "cmake" / "ninlil_esp_storage_sources.cmake"
HOST_CMAKE = REPO_ROOT / "CMakeLists.txt"
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)
COMPONENT_YML = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "idf_component.yml"
)
VERSION_FILE = REPO_ROOT / "ports" / "esp-idf" / "ESP_IDF_VERSION"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "esp-idf.yml"
DOCS_PIN = REPO_ROOT / "docs" / "18-m3-prep-esp-idf-component.md"
DOCS_BASIC = REPO_ROOT / "docs" / "20-m3-basic-esp-idf-platform-adapters.md"
DOCS_STORAGE = REPO_ROOT / "docs" / "21-m3-esp-idf-durable-storage.md"
DOCS_OWNER = REPO_ROOT / "docs" / "22-m3-owner-cell-agent-skeleton.md"
SMOKE_APP = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "CMakeLists.txt"
SMOKE_MAIN = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "main" / "main.c"
SMOKE_SDKCONFIG = REPO_ROOT / "ports" / "esp-idf" / "smoke_app" / "sdkconfig.defaults"
PARTITION_CSV = REPO_ROOT / "ports" / "esp-idf" / "partitions" / "ninlil_storage.csv"
HIL_MAIN = REPO_ROOT / "ports" / "esp-idf" / "hil_app" / "main" / "main.c"
PIN_MIRRORS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CHANGELOG.md",
    REPO_ROOT / "docs" / "06-versioning-and-compatibility.md",
    REPO_ROOT / "docs" / "09-roadmap.md",
    REPO_ROOT / "ports" / "esp-idf" / "README.md",
)
PORT_HEADERS = (
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "clock.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "entropy.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "execution.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task.h",
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "cell_agent.h",
    REPO_ROOT
    / "ports"
    / "esp-idf"
    / "include"
    / "ninlil_esp_idf"
    / "loopback_tx_permit.h",
)

VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\s*$")
SOURCE_LINE_RE = re.compile(r"^\s*((?:src|ports)/[A-Za-z0-9_./-]+\.c)\s*$")
SOURCE_TOKEN_RE = re.compile(
    r"\$\{(?P<var>[A-Za-z0-9_]+)\}"
    r"|(?P<source>(?:src|ports)/[A-Za-z0-9_./-]+\.c)"
)
GLOB_RE = re.compile(r"file\s*\(\s*GLOB", re.IGNORECASE)
ESP_INCLUDE_RE = re.compile(r'#\s*include\s*[<"]esp_')
FREERTOS_INCLUDE_RE = re.compile(r'#\s*include\s*[<"]freertos/')

# Immutable official ESP-IDF container authority (linux/amd64 OCI digest for v5.5.3).
# Tag-only / floating references are rejected; human pin remains ESP_IDF_VERSION.
ESP_IDF_IMMUTABLE_IMAGE = (
    "docker.io/espressif/idf@sha256:"
    "3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
)
ESP_IDF_PLATFORM = "linux/amd64"
ESP_IDF_IMAGE_DIGEST = (
    "sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
)
# Sole authorized launcher: workflow may only invoke this exact argv.
ESP_IDF_DOCKER_SCRIPT_REL = "tools/esp_idf_ci_docker_run.sh"
ESP_IDF_DOCKER_SCRIPT = REPO_ROOT / ESP_IDF_DOCKER_SCRIPT_REL
ESP_IDF_DOCKER_WORKFLOW_RUN = f"bash {ESP_IDF_DOCKER_SCRIPT_REL}"
# Exact workflow invoke: sole launcher + real pin argv (GHA expression expands
# on the runner; the script never embeds ${{ ... }} as shell text).
ESP_IDF_DOCKER_WORKFLOW_RUN_RE = re.compile(
    r"^bash\s+"
    + re.escape(ESP_IDF_DOCKER_SCRIPT_REL)
    + r"(?:\s+(?:\"\$\{\{\s*steps\.pin\.outputs\.version\s*\}\}\"|v[0-9]+\.[0-9]+\.[0-9]+|\"\$\{ESP_IDF_PIN\}\"|\$ESP_IDF_PIN))?\s*$"
)
# Content-hash pin recomputed from the script at check time (self-test freezes it).
# Obsolete tag / floating forms must not appear as an executed image token.
ESP_IDF_TAG_IMAGE_RE = re.compile(
    r"(?:docker\.io/)?espressif/idf:v?[0-9]+(?:\.[0-9]+){0,2}"
)
ESP_IDF_ANY_IMAGE_RE = re.compile(
    r"(?:docker\.io/)?espressif/idf(?::[^\s\"']+|@sha256:[0-9a-f]{64})"
)
DOCKER_BIN_RE = re.compile(r"^(?:.*/)?docker$")
# Shell statement separators outside quotes.
SHELL_SEPARATOR_RE = re.compile(r"(?:&&|\|\||;)")
# docker run options that take a separate value argument.
DOCKER_RUN_VALUE_OPTS = {
    "-v",
    "--volume",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "-e",
    "--env",
    "--name",
    "--network",
    "--entrypoint",
    "--platform",
    "-p",
    "--publish",
    "-m",
    "--memory",
    "--cpus",
    "--cidfile",
    "--label",
    "-l",
    "--env-file",
    "--add-host",
    "--device",
    "--group-add",
    "--hostname",
    "-h",
    "--mount",
    "--runtime",
    "--security-opt",
    "--storage-opt",
    "--sysctl",
    "--tmpfs",
    "--ulimit",
}


def fail(msg: str) -> None:
    print(f"esp_idf_component_packaging_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(REPO_ROOT)}")
    return path.read_text(encoding="utf-8")


def _strip_shell_comment(line: str) -> str:
    """Remove shell comments while preserving # inside single/double quotes."""
    out: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_double:
            out.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            continue
        if ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).rstrip()


def extract_workflow_run_scripts(workflow_text: str) -> list[str]:
    """Structurally collect every mapping value for key `run` in a GHA workflow.

    Handles plain/quoted keys, list items, block `|` / folded `>`, plain and
    quoted scalars, and simple flow mappings `{run: ...}` without requiring
    PyYAML. Unknown/dynamic constructs that cannot be proven safe still feed
    the shell analyzer (fail-closed there).
    """
    scripts: list[str] = []
    scripts.extend(_extract_block_and_inline_key_values(workflow_text, "run"))
    scripts.extend(_extract_flow_map_key_values(workflow_text, "run"))
    return scripts


def extract_workflow_env_values(workflow_text: str) -> list[tuple[str, str]]:
    """Collect (name, value) pairs from mapping key `env` (block or inline).

    Values that embed alternate docker execution (or dynamic docker) fail closed
    when combined with any `run` step authority path.
    """
    pairs: list[tuple[str, str]] = []
    lines = workflow_text.splitlines()
    env_key = r"^(?P<indent>[ \t]*)(?:-\s+)?(?P<q>[\"']?)env(?P=q)\s*:\s*"
    index = 0
    while index < len(lines):
        code = _strip_shell_comment(lines[index])  # YAML # same as shell for quotes
        # Prefer YAML comment strip for env keys (reuse shell strip: same rules).
        match = re.match(env_key + r"$", code)
        if match is not None:
            indent = len(match.group("indent"))
            index += 1
            while index < len(lines):
                line = lines[index]
                if line.strip() == "":
                    index += 1
                    continue
                leading = len(line) - len(line.lstrip(" \t"))
                if leading <= indent:
                    break
                code_line = _strip_shell_comment(line).strip()
                if not code_line:
                    index += 1
                    continue
                # NAME: value  (optional quotes on name)
                kv = re.match(
                    r"^(?P<q>[\"']?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=q)\s*:\s*"
                    r"(?P<val>.*)$",
                    code_line,
                )
                if kv is not None:
                    name = kv.group("name")
                    val = kv.group("val").strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                        val = val[1:-1]
                    pairs.append((name, val))
                index += 1
            continue
        # Inline flow: env: { BAD: "docker run ..." }
        inline = re.match(env_key + r"(?P<body>\{.*\}\s*)$", code)
        if inline is not None:
            body = inline.group("body").strip()
            if body.startswith("{") and body.endswith("}"):
                inner = body[1:-1]
                for km in re.finditer(
                    r"(?:^|,)\s*[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_]*)[\"']?\s*:\s*"
                    r"(?P<val>(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,{}]+))",
                    inner,
                ):
                    val = km.group("val").strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                        val = val[1:-1]
                    pairs.append((km.group("name"), val))
            index += 1
            continue
        index += 1
    return pairs


def _extract_block_and_inline_key_values(workflow_text: str, key: str) -> list[str]:
    lines = workflow_text.splitlines()
    scripts: list[str] = []
    index = 0
    # Optional list dash + optional quotes around key.
    run_key = (
        rf"^(?P<indent>[ \t]*)(?:-\s+)?(?P<q>[\"']?){re.escape(key)}(?P=q)\s*:\s*"
    )
    while index < len(lines):
        code = _strip_shell_comment(lines[index])
        match = re.match(run_key + r"(?P<style>[|>][-+]?)\s*$", code)
        if match is not None:
            indent = len(match.group("indent"))
            style = match.group("style")
            index += 1
            block: list[str] = []
            while index < len(lines):
                line = lines[index]
                if line.strip() == "":
                    block.append("")
                    index += 1
                    continue
                if _strip_shell_comment(line).strip() == "":
                    index += 1
                    continue
                leading = len(line) - len(line.lstrip(" \t"))
                if leading <= indent:
                    break
                block.append(line)
                index += 1
            body = "\n".join(block)
            if style.startswith(">"):
                body = " ".join(
                    part.strip() for part in body.splitlines() if part.strip()
                )
            scripts.append(body)
            continue

        inline = re.match(run_key + r"(?P<body>\S.*)$", code)
        if inline is not None:
            body = inline.group("body").strip()
            if body and body[0] not in "|>" and not body.startswith("#"):
                # Strip matching surrounding quotes from YAML scalar.
                if len(body) >= 2 and body[0] == body[-1] and body[0] in "'\"":
                    body = body[1:-1]
                scripts.append(body)
            index += 1
            continue
        index += 1
    return scripts


def _extract_flow_map_key_values(workflow_text: str, key: str) -> list[str]:
    """Extract key values from simple single-level flow maps on a line."""
    scripts: list[str] = []
    # {run: cmd} or {"run": "cmd"} or { run: cmd, name: x }
    for m in re.finditer(r"\{([^{}]*)\}", workflow_text):
        start = m.start()
        line_start = workflow_text.rfind("\n", 0, start) + 1
        prefix = workflow_text[line_start:start]
        # Skip flow maps that only appear after a YAML comment marker.
        if "#" in prefix:
            # crude: if unquoted # before {, skip
            in_single = in_double = escaped = False
            commented = False
            for ch in prefix:
                if escaped:
                    escaped = False
                    continue
                if ch == "\\" and in_double:
                    escaped = True
                    continue
                if ch == "'" and not in_double:
                    in_single = not in_single
                    continue
                if ch == '"' and not in_single:
                    in_double = not in_double
                    continue
                if ch == "#" and not in_single and not in_double:
                    commented = True
                    break
            if commented:
                continue
        inner = m.group(1)
        for km in re.finditer(
            rf"(?:^|,)\s*[\"']?{re.escape(key)}[\"']?\s*:\s*"
            r"(?P<val>(?:\"(?:\\.|[^\"\\])*\"|"
            r"'(?:\\.|[^'\\])*'|[^,{}]+))",
            inner,
        ):
            val = km.group("val").strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                val = val[1:-1]
            if val:
                scripts.append(val)
    return scripts


def shell_logical_commands(script: str) -> list[str]:
    """Join continuations, drop comments, split on ; / && / || / | pipelines."""
    joined_parts: list[str] = []
    pending = ""
    for raw in script.splitlines():
        code = _strip_shell_comment(raw).strip()
        if not code:
            continue
        if code.endswith("\\"):
            pending += code[:-1].rstrip() + " "
            continue
        pending += code
        joined_parts.append(pending.strip())
        pending = ""
    if pending.strip():
        joined_parts.append(pending.strip())

    commands: list[str] = []
    for part in joined_parts:
        for stmt in _split_shell_statements(part):
            # Further split pipelines so `true | docker run` is visible.
            commands.extend(_split_shell_pipelines(stmt))
    return [c for c in commands if c]


def _split_shell_statements(command: str) -> list[str]:
    """Split one shell line on ; / && / || while respecting quotes."""
    statements: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and in_double:
            buf.append(ch)
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if command.startswith("&&", i) or command.startswith("||", i):
                stmt = "".join(buf).strip()
                if stmt:
                    statements.append(stmt)
                buf = []
                i += 2
                continue
            if ch == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    statements.append(stmt)
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    stmt = "".join(buf).strip()
    if stmt:
        statements.append(stmt)
    return statements


def _split_shell_pipelines(command: str) -> list[str]:
    """Split on bare | (not ||) outside quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    while i < len(command):
        ch = command[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and in_double:
            buf.append(ch)
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if (
            not in_single
            and not in_double
            and ch == "|"
            and not command.startswith("||", i)
            and (i == 0 or command[i - 1] != "|")
        ):
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    part = "".join(buf).strip()
    if part:
        parts.append(part)
    return parts


def tokenize_shell_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError as exc:
        fail(f"cannot tokenize executable shell command {command!r}: {exc}")
        raise  # pragma: no cover


def _is_docker_bin(token: str) -> bool:
    return bool(DOCKER_BIN_RE.match(token))


def _is_dynamic_token(token: str) -> bool:
    """True when a token cannot be resolved statically (vars/subst/globs)."""
    if token.startswith("$") or "${" in token:
        return True
    if "`" in token:
        return True
    if "$(" in token:
        return True
    return False


def _skip_assignments_and_wrappers(tokens: list[str], start: int = 0) -> int:
    """Skip env assignments and sudo/env/command wrappers before a command."""
    i = start
    while i < len(tokens):
        tok = tokens[i]
        # VAR=value assignment prefix (FOO=1 docker run)
        if (
            "=" in tok
            and not tok.startswith("-")
            and not _is_docker_bin(tok)
            and not tok.startswith("$")
            and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok)
        ):
            i += 1
            continue
        if tok in {"sudo", "command", "nice", "nohup", "time", "stdbuf"}:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-") and not _is_docker_bin(
                tokens[i]
            ):
                if tokens[i] in {"-u", "-g", "-C"} and i + 1 < len(tokens):
                    i += 2
                else:
                    i += 1
            continue
        if tok == "env":
            i += 1
            while i < len(tokens):
                t = tokens[i]
                if t.startswith("-"):
                    if t in {"-u", "-C"} and i + 1 < len(tokens):
                        i += 2
                    else:
                        i += 1
                    continue
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
                    i += 1
                    continue
                break
            continue
        break
    return i


# Shells / interpreters that can hide docker inside -c/-lc scripts.
_SHELL_INTERPRETERS = {
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "busybox",
}


def _command_has_dynamic_docker(tokens: list[str]) -> bool:
    """Fail-closed detection of unprovable docker execution forms."""
    if not tokens:
        return False
    # bash -c 'docker run ...' / sh -lc "..."
    i = _skip_assignments_and_wrappers(tokens, 0)
    if i < len(tokens):
        base = tokens[i].rsplit("/", 1)[-1]
        if base in _SHELL_INTERPRETERS:
            # Any -c/-lc with docker substring is dynamic.
            joined = " ".join(tokens[i:])
            if "docker" in joined:
                return True
    # "$D" run / $DOCKER run
    for idx, tok in enumerate(tokens):
        if _is_dynamic_token(tok) and "docker" in tok.lower():
            return True
        if _is_dynamic_token(tok) and idx + 1 < len(tokens) and tokens[idx + 1] == "run":
            return True
    # eval ...
    if any(t == "eval" for t in tokens) and any("docker" in t for t in tokens):
        return True
    return False


def parse_docker_run_invocation(tokens: list[str]) -> dict[str, object] | None:
    """Parse a statically resolvable `docker … run … IMAGE` invocation."""
    if _command_has_dynamic_docker(tokens):
        fail(
            "esp-idf.yml contains dynamic/unprovable docker execution "
            f"(fail-closed): {tokens!r}"
        )

    i = _skip_assignments_and_wrappers(tokens, 0)
    if i >= len(tokens) or not _is_docker_bin(tokens[i]):
        # No docker binary at command head — if docker appears later as data only,
        # ignore; if it looks like a second command, fail closed.
        if any(_is_docker_bin(t) or t.endswith("/docker") for t in tokens[i + 1 :]):
            fail(
                "esp-idf.yml has non-leading docker binary (unprovable form): "
                f"{tokens!r}"
            )
        return None

    j = i + 1
    # docker global options before subcommand (includes --context).
    while j < len(tokens) and tokens[j].startswith("-") and tokens[j] != "run":
        opt = tokens[j]
        if opt.startswith("--") and "=" in opt:
            j += 1
            continue
        # Global options that take a value.
        if opt in {
            "-H",
            "--host",
            "-c",
            "--config",
            "-l",
            "--log-level",
            "--context",
            "-D",
            "--debug",
        }:
            # boolean longs without value:
            if opt in {"-D", "--debug"}:
                j += 1
            else:
                if j + 1 >= len(tokens):
                    fail(f"docker global option {opt} missing value")
                j += 2
            continue
        # Unknown global flag — fail closed rather than mis-parse.
        if opt.startswith("-"):
            # treat as boolean short/long without value
            j += 1
            continue
        break

    if j >= len(tokens) or tokens[j] != "run":
        return None
    j += 1

    platforms: list[str] = []
    while j < len(tokens):
        tok = tokens[j]
        if tok == "--":
            j += 1
            break
        if tok.startswith("--platform="):
            platforms.append(tok.split("=", 1)[1])
            j += 1
            continue
        if tok == "--platform":
            if j + 1 >= len(tokens):
                fail("docker run --platform missing value")
            platforms.append(tokens[j + 1])
            j += 2
            continue
        if tok.startswith("-"):
            if "=" in tok:
                j += 1
                continue
            base = tok
            if base in DOCKER_RUN_VALUE_OPTS:
                if j + 1 >= len(tokens):
                    fail(f"docker run option {base} missing value")
                j += 2
            else:
                j += 1
            continue
        break

    if j >= len(tokens):
        fail("docker run missing image argument")
    image = tokens[j]
    if _is_dynamic_token(image):
        fail(f"docker run IMAGE is dynamic/unprovable: {image!r}")
    command_args = tokens[j + 1 :]
    return {
        "tokens": tokens[i:],
        "image": image,
        "platforms": platforms,
        "command_args": command_args,
    }


def _env_value_looks_like_docker_execution(value: str) -> bool:
    """True when an env scalar embeds a docker run / dynamic docker command."""
    lowered = value.lower()
    if "docker" not in lowered:
        return False
    # Direct docker run embedding.
    if re.search(r"(?:^|[;&|`\n]|\b)\s*(?:.*/)?docker(?:\s|$)", value):
        return True
    if "docker run" in lowered:
        return True
    if re.search(r"\$\{?docker", lowered):
        return True
    return False


def assert_env_docker_dataflow(workflow_text: str) -> None:
    """Fail closed on env-borne or dynamically-indirect docker execution.

    Contract:
    - Any `env` scalar that embeds docker (run/binary/image/indirection) is an
      alternate executable docker path and rejects, even when a sibling `run`
      does not obviously expand it.
    - Ordinary GitHub Actions expressions without docker remain allowed.
    """
    for name, value in extract_workflow_env_values(workflow_text):
        if "docker" not in value.lower() and not _env_value_looks_like_docker_execution(
            value
        ):
            continue
        fail(
            f"esp-idf.yml env {name} embeds alternate/dynamic docker execution "
            f"(fail-closed): {value!r}"
        )


def extract_executable_docker_runs(workflow_text: str) -> list[dict[str, object]]:
    """Enumerate every statically provable docker run in workflow run scripts."""
    assert_env_docker_dataflow(workflow_text)
    runs: list[dict[str, object]] = []
    for script in extract_workflow_run_scripts(workflow_text):
        for command in shell_logical_commands(script):
            tokens = tokenize_shell_command(command)
            # Fail closed if this command hides dynamic docker.
            if _command_has_dynamic_docker(tokens):
                fail(
                    "esp-idf.yml contains dynamic/unprovable docker execution "
                    f"(fail-closed): {command!r}"
                )
            parsed = parse_docker_run_invocation(tokens)
            if parsed is not None:
                runs.append(parsed)
    return runs



def _workflow_run_scripts_semantic(workflow_text: str) -> list[str]:
    """Semantic YAML extraction of every step run scalar (Unicode keys resolve)."""
    tools = pathlib.Path(__file__).resolve().parent
    import sys
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    from yaml_semantic import load_yaml_document, step_run, walk_job_steps  # type: ignore

    try:
        doc = load_yaml_document(workflow_text)
    except ValueError as exc:
        fail(f"esp-idf.yml YAML semantic parse failed: {exc}")
    scripts: list[str] = []
    for _job, step_index, step in walk_job_steps(doc):
        if step_index is None:
            continue
        run = step_run(step)
        if run is not None and str(run).strip():
            scripts.append(str(run))
    return scripts


def _forbidden_shell_indirection(script: str) -> str | None:
    """Return a reason if script uses alias/function/eval/source/sh -c forms."""
    # Comment-strip then scan.
    lines = []
    for raw in script.splitlines():
        lines.append(_strip_shell_comment(raw))
    body = "\n".join(lines)
    patterns = [
        (r"\beval\b", "eval"),
        (r"\bsource\b", "source"),
        (r"(?<!\S)\.\s+/", "dot-source"),
        (r"\balias\s+", "alias"),
        (r"\bfunction\s+", "function"),
        (r"\bshopt\s+-s\s+expand_aliases\b", "expand_aliases"),
        (r"\bbash\s+-c\b", "bash -c"),
        (r"\bsh\s+-c\b", "sh -c"),
        (r"\bzsh\s+-c\b", "zsh -c"),
        (r"\$\(\s*docker\b", "command-substitution docker"),
        (r"`[^`]*docker", "backtick docker"),
    ]
    for pat, name in patterns:
        if re.search(pat, body):
            return name
    return None


def assert_esp_idf_docker_run_authority(
    workflow_text: str,
    script_text: str | None = None,
) -> None:
    """Bind docker execution to the sole authorized launcher script.

    Contract:
    - Workflow semantic `run` steps must not embed docker binaries / aliases.
    - Exactly one workflow run equals `bash tools/esp_idf_ci_docker_run.sh`.
    - That script's bytes are hashed; it contains exactly one docker run with
      the immutable image digest and --platform linux/amd64.
    - alias / function / eval / sh -c / source / expand_aliases fail closed.
    """
    if script_text is None:
        if not ESP_IDF_DOCKER_SCRIPT.is_file():
            fail(f"missing sole docker launcher {ESP_IDF_DOCKER_SCRIPT_REL}")
        script_bytes = ESP_IDF_DOCKER_SCRIPT.read_bytes()
        script_text = script_bytes.decode("utf-8")
    else:
        script_bytes = script_text.encode("utf-8")
    script_sha = hashlib.sha256(script_bytes).hexdigest()

    # --- Script authority ---
    if script_text.count("docker run") != 1:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} must contain exactly one 'docker run', "
            f"got {script_text.count('docker run')}"
        )
    if ESP_IDF_IMMUTABLE_IMAGE not in script_text:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} missing exact immutable image "
            f"{ESP_IDF_IMMUTABLE_IMAGE}"
        )
    if f"--platform {ESP_IDF_PLATFORM}" not in script_text:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} missing exact --platform {ESP_IDF_PLATFORM}"
        )
    # Tag-only / floating image forms inside the script.
    if ESP_IDF_TAG_IMAGE_RE.search(script_text):
        # Allow only if they appear solely inside comments.
        for line in script_text.splitlines():
            code = _strip_shell_comment(line)
            if ESP_IDF_TAG_IMAGE_RE.search(code):
                fail(
                    f"{ESP_IDF_DOCKER_SCRIPT_REL} contains tag-only image token "
                    f"in executable text: {code.strip()!r}"
                )
    reason = _forbidden_shell_indirection(script_text)
    # Script may mention expand_aliases only to *disable* it — allow unalias /
    # shopt -u expand_aliases, reject shopt -s expand_aliases / alias defs.
    if reason and reason not in {"expand_aliases"}:
        # expand_aliases: only fail if enabling
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} contains forbidden shell form "
            f"{reason!r}"
        )
    if re.search(r"\bshopt\s+-s\s+expand_aliases\b", script_text):
        fail(f"{ESP_IDF_DOCKER_SCRIPT_REL} must not enable expand_aliases")
    if re.search(r"(?m)^\s*alias\s+", script_text):
        fail(f"{ESP_IDF_DOCKER_SCRIPT_REL} must not define aliases")
    if re.search(r"\beval\b", _strip_shell_comment(script_text)):
        # check line by line
        for line in script_text.splitlines():
            if re.search(r"\beval\b", _strip_shell_comment(line)):
                fail(f"{ESP_IDF_DOCKER_SCRIPT_REL} must not use eval")

    # Parse the single docker run line-group from the script (outside heredoc).
    outer = script_text.split("<<'NINLIL_ESP_CI'")[0]
    runs = []
    for command in shell_logical_commands(outer):
        tokens = tokenize_shell_command(command)
        if any(_is_docker_bin(t) for t in tokens) or (
            tokens and _is_docker_bin(tokens[0])
        ):
            parsed = parse_docker_run_invocation(tokens)
            if parsed is not None:
                runs.append(parsed)
    if len(runs) != 1:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} outer shell must have exactly one "
            f"docker run, got {len(runs)}"
        )
    run = runs[0]
    if str(run["image"]) != ESP_IDF_IMMUTABLE_IMAGE:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} IMAGE must be {ESP_IDF_IMMUTABLE_IMAGE!r}, "
            f"got {run['image']!r}"
        )
    platforms = list(run["platforms"])  # type: ignore[arg-type]
    if platforms != [ESP_IDF_PLATFORM]:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} platform must be exactly "
            f"[{ESP_IDF_PLATFORM}], got {platforms!r}"
        )

    # --- Workflow authority: only exact script invoke; no docker elsewhere ---
    # Script must not embed GitHub Actions expressions as shell text (P0).
    outer_only = script_text.split("<<'NINLIL_ESP_CI'")[0]
    outer_code_lines = []
    for raw in outer_only.splitlines():
        code = _strip_shell_comment(raw)
        if code.strip():
            outer_code_lines.append(code)
    outer_code = "\n".join(outer_code_lines)
    if "${{" in outer_code:
        fail(
            f"{ESP_IDF_DOCKER_SCRIPT_REL} outer shell must not embed GitHub Actions "
            "expressions; pass pin as argv/env"
        )
    if "EXPECTED_ESP_IDF_PIN" not in script_text or 'v5.5.3' not in script_text:
        fail(f"{ESP_IDF_DOCKER_SCRIPT_REL} missing closed EXPECTED_ESP_IDF_PIN=v5.5.3")

    scripts = _workflow_run_scripts_semantic(workflow_text)
    dockerish = []
    script_invokes = 0
    for script in scripts:
        stripped = script.strip()
        # Single-line or first-line exact launcher invoke with pin argv.
        first_line = stripped.splitlines()[0].strip() if stripped else ""
        if ESP_IDF_DOCKER_WORKFLOW_RUN_RE.match(first_line) or ESP_IDF_DOCKER_WORKFLOW_RUN_RE.match(
            stripped
        ):
            script_invokes += 1
            continue
        # Any other run must not reference docker executable forms.
        reason = _forbidden_shell_indirection(script)
        if reason:
            fail(
                f"esp-idf.yml run contains forbidden shell form {reason!r}: "
                f"{script[:120]!r}"
            )
        # Fail closed on docker binary / image tokens outside the launcher.
        for command in shell_logical_commands(script):
            tokens = tokenize_shell_command(command)
            if any(_is_docker_bin(t) for t in tokens):
                dockerish.append(command)
            if ESP_IDF_ANY_IMAGE_RE.search(command) or "docker run" in command:
                dockerish.append(command)
            # alias d=do''cker style
            if re.search(r"alias\s+\w+=", command) and "dock" in command.replace(
                "''", ""
            ):
                dockerish.append(command)
    if dockerish:
        fail(
            "esp-idf.yml must not embed docker execution outside "
            f"{ESP_IDF_DOCKER_SCRIPT_REL}; found {dockerish[:3]!r}"
        )
    if script_invokes != 1:
        fail(
            "esp-idf.yml must contain exactly one sole-launcher invoke "
            f"({ESP_IDF_DOCKER_SCRIPT_REL} + pin argv), got {script_invokes}"
        )

    # Env values must not embed docker.
    assert_env_docker_dataflow(workflow_text)

    # Record script hash for diagnostics (not a floating claim).
    print(
        f"esp_idf docker authority: script={ESP_IDF_DOCKER_SCRIPT_REL} "
        f"sha256={script_sha}"
    )



def read_pin() -> str:
    raw = read_text(VERSION_FILE).strip()
    if not VERSION_RE.match(raw):
        fail(f"ESP_IDF_VERSION must be concrete vX.Y.Z, got {raw!r}")
    return raw


def pin_numeric(pin: str) -> str:
    m = VERSION_RE.match(pin)
    assert m is not None
    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"


def authority_sources(text: str) -> list[str]:
    sources: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip().rstrip(")")
        m = SOURCE_LINE_RE.match(code)
        if m:
            rel = m.group(1)
            if rel not in seen:
                seen.add(rel)
                sources.append(rel)
    return sources


def list_sources_in_var(text: str, var_name: str) -> list[str]:
    """Expand a CMake set() list, including nested ${VAR} references."""
    pattern = re.compile(
        r"set\(\s*(?P<name>[A-Za-z0-9_]+)\s*(?P<body>.*?)^\s*\)",
        re.MULTILINE | re.DOTALL,
    )
    bodies = {m.group("name"): m.group("body") for m in pattern.finditer(text)}

    def expand(name: str, active: tuple[str, ...]) -> list[str]:
        if name in active:
            fail(f"recursive CMake source variable: {' -> '.join(active + (name,))}")
        body = bodies.get(name)
        if body is None:
            fail(f"undefined CMake source variable {name}")
        code = "\n".join(line.split("#", 1)[0] for line in body.splitlines())
        expanded: list[str] = []
        for token in SOURCE_TOKEN_RE.finditer(code):
            nested = token.group("var")
            source = token.group("source")
            if nested is not None:
                expanded.extend(expand(nested, active + (name,)))
            elif source is not None:
                expanded.append(source)
        return expanded

    result: list[str] = []
    seen: set[str] = set()
    for source in expand(var_name, ()):
        if source in seen:
            fail(f"duplicate source after CMake expansion in {var_name}: {source}")
        seen.add(source)
        result.append(source)
    return result


def assert_no_esp_freertos(rel: str, text: str) -> None:
    if ESP_INCLUDE_RE.search(text):
        fail(f"source must not include ESP-IDF header: {rel}")
    if FREERTOS_INCLUDE_RE.search(text):
        fail(f"source must not include FreeRTOS header: {rel}")


def check() -> None:
    pin = read_pin()
    numeric = pin_numeric(pin)

    host = read_text(HOST_CMAKE)
    if "ninlil_runtime_private_sources.cmake" not in host:
        fail("host CMakeLists missing private authority")
    if "ninlil_esp_idf_port_sources.cmake" not in host:
        fail("host CMakeLists missing ESP-IDF port authority")
    if "ninlil_esp_storage_sources.cmake" not in host:
        fail("host CMakeLists missing storage authority")
    if "esp_idf_port_logic" not in host:
        fail("host missing esp_idf_port_logic test")

    component = read_text(COMPONENT_CMAKE)
    if "ninlil_esp_idf_port_sources.cmake" not in component:
        fail("component missing port authority")
    if "NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES" not in component:
        fail("component must consume port ALL sources")
    if "ninlil_esp_storage_sources.cmake" not in component:
        fail("component missing durable-storage authority")
    if "NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES" not in component:
        fail("component must consume storage TARGET sources")
    # Public SDK boundary: src/** must not appear under INCLUDE_DIRS (only PRIV).
    public_block = re.search(
        r"(?m)^[ \t]*INCLUDE_DIRS[ \t]*\n(?P<body>.*?)"
        r"(?=^[ \t]*PRIV_INCLUDE_DIRS\b)",
        component,
        re.DOTALL | re.MULTILINE,
    )
    if public_block is None:
        fail("component idf_component_register missing INCLUDE_DIRS/PRIV_INCLUDE_DIRS")
    if re.search(r"src/transport|src/model|src/runtime|src/radio", public_block.group("body")):
        fail(
            "component public INCLUDE_DIRS must not export src/** "
            "(use PRIV_INCLUDE_DIRS; C1 is include/ninlil/byte_stream.h)"
        )
    if "src/transport" not in component.split("PRIV_INCLUDE_DIRS", 1)[-1]:
        fail("component PRIV_INCLUDE_DIRS must still list src/transport for private TUs")
    usb_cdc = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "usb_cdc.h"
    )
    if '#include "byte_stream.h"' in usb_cdc:
        fail('usb_cdc.h must include "ninlil/byte_stream.h", not bare byte_stream.h')
    if "ninlil/byte_stream.h" not in usb_cdc:
        fail("usb_cdc.h must include formal ninlil/byte_stream.h")
    if not (REPO_ROOT / "include" / "ninlil" / "byte_stream.h").is_file():
        fail("missing formal public header include/ninlil/byte_stream.h")
    # N6 production stack-usage: every NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    # member must get -fstack-usage and -Wframe-larger-than=2048 (docs/30 §20.4.1).
    if "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES" not in component:
        fail(
            "component must reference NINLIL_N6_PRODUCTION_RELATIVE_SOURCES "
            "for N6 stack-usage flags"
        )
    if "-fstack-usage" not in component:
        fail("component missing -fstack-usage (required for N6 .su generation)")
    if "-Wframe-larger-than=2048" not in component:
        fail("component missing -Wframe-larger-than=2048 for N6 frame ceiling")
    if not re.search(
        r"NINLIL_N6_PRODUCTION_RELATIVE_SOURCES[\s\S]{0,800}?"
        r"-fstack-usage[\s\S]{0,200}?-Wframe-larger-than=2048",
        component,
    ):
        fail(
            "component must apply -fstack-usage and -Wframe-larger-than=2048 "
            "to NINLIL_N6_PRODUCTION_RELATIVE_SOURCES (not storage-only)"
        )
    component_code = "\n".join(
        line.split("#", 1)[0] for line in component.splitlines()
    )
    if GLOB_RE.search(component_code):
        fail("component must not GLOB")
    for req in (
        "esp_timer",
        "esp_hw_support",
        "bootloader_support",
        "freertos",
        "spi_flash",
        "esp_partition",
        "wear_levelling",
    ):
        if req not in component:
            fail(f"component should PRIV_REQUIRES {req}")

    portable_text = read_text(PORTABLE_AUTHORITY)
    portable_sources = authority_sources(portable_text)
    for rel in portable_sources:
        if rel.startswith("ports/"):
            fail(f"portable authority must not list {rel}")
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        assert_no_esp_freertos(rel, text)

    port_text = read_text(PORT_AUTHORITY)
    pure_sources = list_sources_in_var(
        port_text, "NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES"
    )
    backend_sources = list_sources_in_var(
        port_text, "NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES"
    )
    if not pure_sources or not backend_sources:
        fail("port authority pure/backend empty")
    for rel in pure_sources:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        assert_no_esp_freertos(rel, text)
    for rel in backend_sources:
        if not (REPO_ROOT / rel).is_file():
            fail(f"missing backend {rel}")

    required = {
        "ports/esp-idf/src/entropy_lifecycle_logic.c",
        "ports/esp-idf/src/entropy_publish_logic.c",
        "ports/esp-idf/src/execution_init_logic.c",
        "ports/esp-idf/src/owner_mailbox_logic.c",
        "ports/esp-idf/src/owner_lifecycle_logic.c",
        "ports/esp-idf/src/owner_publish_logic.c",
        "ports/esp-idf/src/owner_authority_logic.c",
        "ports/esp-idf/src/cell_assignment_logic.c",
        "ports/esp-idf/src/control_boundary_logic.c",
        "ports/esp-idf/src/loopback_tx_permit_logic.c",
        "ports/esp-idf/src/tx_gate_validate.c",
        "ports/esp-idf/src/pointer_range_logic.c",
        "ports/esp-idf/src/abi_header_stage_logic.c",
        "ports/esp-idf/src/owner_config_stage_logic.c",
        "ports/esp-idf/src/tx_gate_lease_logic.c",
        "ports/esp-idf/src/esp_idf_clock.c",
        "ports/esp-idf/src/esp_idf_entropy.c",
        "ports/esp-idf/src/esp_idf_execution.c",
        "ports/esp-idf/src/esp_idf_owner_task.c",
        "ports/esp-idf/src/esp_idf_cell_agent.c",
        "ports/esp-idf/src/esp_idf_loopback_tx_permit.c",
    }
    all_port = set(pure_sources) | set(backend_sources)
    if not required.issubset(all_port):
        fail(f"port sources missing {required - all_port}")

    storage_text = read_text(STORAGE_AUTHORITY)
    storage_target = list_sources_in_var(
        storage_text, "NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES"
    )
    exact_storage_target = [
        "ports/esp-idf/storage/model/esp_storage_codec.c",
        "ports/esp-idf/storage/model/esp_storage_model.c",
        "ports/esp-idf/storage/esp/esp_storage_flash_media.c",
    ]
    if storage_target != exact_storage_target:
        fail(
            "target storage source set must be exactly model2+flash1, got "
            f"{storage_target}"
        )
    for required_storage in exact_storage_target:
        if required_storage not in storage_text:
            fail(f"storage authority missing {required_storage}")
        if not (REPO_ROOT / required_storage).is_file():
            fail(f"missing storage source {required_storage}")
    if "ports/esp-idf/storage/host/esp_storage_host_media.c" in storage_target:
        fail("target storage authority must exclude host media")

    # Host-media concrete workspace + private_simulate seams must stay
    # compile-excluded under ESP_PLATFORM (docs/21 host-only dual-slot).
    workspace_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "private"
        / "esp_storage_workspace.h"
    )
    workspace_text = read_text(workspace_hdr)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"(?:/\*[\s\S]*?\*/\s*\n)?"
        r"struct\s+ninlil_port_esp_storage_host_media\s*\{",
        workspace_text,
    ):
        fail(
            "esp_storage_workspace.h host_media struct must be "
            "compile-excluded under ESP_PLATFORM"
        )
    private_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "private"
        / "esp_storage_private.h"
    )
    private_text = read_text(private_hdr)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"(?:/\*[\s\S]*?\*/\s*\n)?"
        r"void\s+ninlil_port_esp_storage_private_simulate_crash\s*\(",
        private_text,
    ):
        fail(
            "esp_storage_private.h private_simulate_crash must be "
            "compile-excluded under ESP_PLATFORM"
        )
    model_src = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "storage"
        / "model"
        / "esp_storage_model.c"
    )
    model_text = read_text(model_src)
    if not re.search(
        r"#if\s+!defined\s*\(\s*ESP_PLATFORM\s*\)\s*\n"
        r"void\s+ninlil_port_esp_storage_private_simulate_crash\s*\(",
        model_text,
    ):
        fail(
            "esp_storage_model.c private_simulate_crash definition must be "
            "compile-excluded under ESP_PLATFORM"
        )

    for header in PORT_HEADERS:
        h = read_text(header)
        if ESP_INCLUDE_RE.search(h) or FREERTOS_INCLUDE_RE.search(h):
            fail(f"port header must not include ESP/FreeRTOS: {header.name}")
        if "ninlil/platform.h" not in h:
            fail(f"port header must include platform.h: {header.name}")

    yml = read_text(COMPONENT_YML)
    if f"=={numeric}" not in yml or "esp32s3" not in yml:
        fail("idf_component.yml pin/target mismatch")

    ci = read_text(CI_WORKFLOW)
    if pin not in ci or "esp32s3" not in ci:
        fail("esp-idf.yml pin/target mismatch")
    # Authority is the sole launcher script + exact workflow invoke.
    assert_esp_idf_docker_run_authority(ci)
    launcher = read_text(ESP_IDF_DOCKER_SCRIPT)
    # Target build authority lives in the launcher script (not inline workflow).
    authority_text = ci + "\n" + launcher
    if re.search(r"\bctest\b", authority_text):
        fail("esp-idf CI authority must not run host ctest")
    for needle in (
        "ports/esp-idf/hil_app",
        "esp_storage_map_gate.py",
        "esp_storage_stack_gate.py",
        "esp_storage_public_api_gate.py",
        "xtensa-esp32s3-elf-readelf",
        "ninlil_m3_combined_smoke.map",
        "ninlil_storage_powercut_hil.map",
        "ninlil_storage_powercut_hil.elf",
        # N6 ESP stack-usage collection + frame gate (docs/30 §20.4.1)
        "n6_frame_stack_gate.py",
        "--esp-su-dir",
        "--su-dir",
        "n6_context_store.c.su",
        "n6_record_codec.c.su",
        "n6_crypto_host.c.su",
        "ninlil_n6_su",
        "exactly 1 match",
        ESP_IDF_DOCKER_SCRIPT_REL,
        "N6_SU_DIR=",
        "n6_frame_stack_gate.py",
        "--esp-su-dir",
        "--su-dir",
    ):
        if needle not in authority_text:
            fail(f"esp-idf CI authority missing storage/N6 target gate {needle!r}")
    if "bash tools/esp_idf_ci_docker_run.sh" not in ci:
        fail("esp-idf.yml must invoke sole launcher bash tools/esp_idf_ci_docker_run.sh")
    # Host substitute for ESP N6 .su is forbidden.
    if re.search(
        r"--esp-su-dir[=\s]+[^\n]*ninlil_runtime_private\.dir",
        authority_text,
    ):
        fail(
            "esp-idf CI --esp-su-dir must not use host "
            "ninlil_runtime_private.dir (host substitute forbidden)"
        )
    # N6 .su collection must not use head -1 (duplicate-selection weakening).
    n6_ci_m = re.search(
        r"N6_SU_DIR=.*?n6_frame_stack_gate\.py.*?(?:\n\s*[A-Za-z#]|\Z)",
        authority_text,
        re.S,
    )
    n6_ci = n6_ci_m.group(0) if n6_ci_m else ""
    if n6_ci and ("head -1" in n6_ci or "head -n 1" in n6_ci):
        fail(
            "esp-idf CI N6 .su collection must not use head -1 "
            "(require find match count exactly 1)"
        )
    if n6_ci and not re.search(r"exactly 1 match|-ne 1", n6_ci):
        fail(
            "esp-idf CI N6 .su collection must enforce exactly 1 find match "
            "per exact .su basename"
        )
    # Official target archive inspection must declare --archive-kind target
    # (host CTest uses host kind; refuse silent default / inverted wiring).
    if "--archive-kind target" not in authority_text:
        fail(
            "esp-idf CI public_api_gate must pass --archive-kind target "
            "(host CTest uses --archive-kind host)"
        )
    if "--archive-kind host" in launcher:
        fail(
            "esp-idf launcher must not pass --archive-kind host "
            "(target workflow inspects the official ESP archive)"
        )
    # Both official maps must be required (not smoke-only).
    if launcher.count("esp_storage_map_gate.py") < 2:
        fail("esp-idf launcher must run esp_storage_map_gate.py on smoke and HIL maps")

    docs = read_text(DOCS_PIN)
    if pin not in docs or "M3-prep" not in docs:
        fail("docs/18 pin/M3-prep missing")

    docs19 = read_text(DOCS_BASIC)
    for needle in (
        "one-shot",
        "immutable",
        "DISABLING",
        "ACQUIRING cancel",
        "NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX",
        "RETIRED",
        "TaskHandle",
        "owner-task",
        "esp_timer",
        "BOOTLOADER_RNG",
        "compile/link",
        "M3 incomplete",
    ):
        if needle not in docs19:
            fail(f"docs/20 must document {needle!r}")

    docs21 = read_text(DOCS_STORAGE)
    for needle in (
        "PSRAM",
        "ESP_UNPROVEN",
        "COMMIT_UNKNOWN",
        "iterator",
        "final-net",
        "HIL 未実行",
    ):
        if needle not in docs21:
            fail(f"docs/21 must document {needle!r}")

    docs22 = read_text(DOCS_OWNER)
    for needle in (
        "inflight",
        "FAILED_LIVE",
        "FAILED_JOINED",
        "JOIN_ACK",
        "vTaskDelete",
        "prvDeleteTCB",
        "start_gate",
        "4096",
        "StackType_t",
        "experimental",
        "logical_bytes",
        "lease",
        "MAX_TX_GATE_LEASES",
        "mux_ready",
        "M3 incomplete",
        "self-stop",
        "single-use",
        "non-overlap",
        "uintptr_t",
        "pointer-compare",
        "detect_invalid_pointer_pairs",
        "tx_gate_lease_registry.h",
        "ABI header staging",
        "declared struct_size",
        "detail/",
        "Target smoke",
        "trusted initial publish",
        "exact",
        "struct_size` 除外",
        "post-write reread",
        "owner_config_stage",
    ):
        if needle not in docs22:
            fail(f"docs/22 must document {needle!r}")

    owner_backend = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "esp_idf_owner_task.c"
    )
    if "ninlil_esp_idf_owner_config_stage" not in owner_backend:
        fail("owner_task_init path must call owner_config_stage helper")
    host_test = read_text(
        REPO_ROOT / "tests" / "port" / "owner_cell_agent_logic_test.c"
    )
    if "ninlil_esp_idf_owner_config_stage" not in host_test:
        fail("host owner test must exercise owner_config_stage (not generic only)")
    if "|| (declared - known)" in host_test or "|| declared - known" in host_test:
        fail("owner logic test has vacuous OR geometry assertion")

    host = read_text(HOST_CMAKE)
    if "owner_cell_agent_logic" not in host:
        fail("host CMakeLists missing owner_cell_agent_logic test")
    if "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER" not in host:
        fail("host CMakeLists missing pointer-compare sanitizer option")
    if "esp_storage_dual_slot_conformance" not in host:
        fail("host CMakeLists missing esp_storage_dual_slot_conformance test")
    if "esp_storage_stack_gate" not in host:
        fail("host CMakeLists missing esp_storage_stack_gate test")
    if "esp_storage_wear_gate" not in host:
        fail("host CMakeLists missing esp_storage_wear_gate test")
    if "esp_storage_budget_gate" not in host:
        fail("host CMakeLists missing esp_storage_budget_gate test")
    if "esp_storage_public_api_gate.py" not in host:
        fail("host CMakeLists missing esp_storage_public_api_gate test")
    # Host CTest archive is the dual-slot host library (includes host media
    # test seams). Kind must be host; target kind here would false-fail on
    # intentional ninlil_port_esp_storage_host_media_ops.
    if "--archive-kind host" not in host:
        fail(
            "host CMakeLists public_api_gate must pass --archive-kind host "
            "(refuse missing kind / silent target rules on host archive)"
        )
    if "--archive-kind target" in host:
        fail(
            "host CMakeLists must not pass --archive-kind target "
            "(official ESP archive is gated in esp-idf.yml)"
        )

    ci_host = read_text(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    if "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER" not in ci_host:
        fail("host ci.yml missing pointer-compare sanitizer job")
    if "detect_invalid_pointer_pairs=2" not in ci_host:
        fail("host ci.yml missing detect_invalid_pointer_pairs=2")

    owner_api = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "owner_task.h"
    )
    if "tx_gate_lease_registry_t" in owner_api or "tx_gate_lease_slot_t" in owner_api:
        fail("public owner_task.h must not expose registry/slot internal types")
    if "ABI staging" not in owner_api:
        fail("public owner_task.h must document ABI staging")

    old_reg = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "include"
        / "ninlil_esp_idf"
        / "tx_gate_lease_registry.h"
    )
    if old_reg.is_file():
        fail("registry layout must not remain outside detail/")
    reg_hdr = (
        REPO_ROOT
        / "ports"
        / "esp-idf"
        / "include"
        / "ninlil_esp_idf"
        / "detail"
        / "tx_gate_lease_registry.h"
    )
    if not reg_hdr.is_file():
        fail("missing detail/tx_gate_lease_registry.h unstable layout header")
    if "Unstable concrete storage detail" not in read_text(reg_hdr):
        fail("detail registry header must declare unstable storage detail")

    # Trusted/nested helpers must not ship as default global ELF symbols.
    # Prefer static inline (local / absent in nm), not merely -fvisibility=hidden.
    if "cell_config_stage_logic.c" in pure_sources:
        fail("cell_config_stage_nested_owner must not be a pure .c TU (use static inline)")
    lease_c = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "tx_gate_lease_logic.c")
    if re.search(
        r"(?m)^(?!\s*static\s).*set_ops_trusted\s*\(", lease_c
    ) or "set_ops_trusted" in lease_c:
        fail("set_ops_trusted must not be defined in tx_gate_lease_logic.c")
    owner_c = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "esp_idf_owner_task.c")
    if "publish_tx_gate_trusted" in owner_c:
        fail("publish_tx_gate_trusted must not be defined in esp_idf_owner_task.c")
    lease_h = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "tx_gate_lease_logic.h")
    if "static inline" not in lease_h or "set_ops_trusted" not in lease_h:
        fail("set_ops_trusted must be static inline in private header")
    trusted_h = read_text(REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_tx_gate_trusted.h")
    if "static inline" not in trusted_h or "publish_tx_gate_trusted" not in trusted_h:
        fail("publish_tx_gate_trusted must be static inline in private header")
    cell_stage_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "cell_config_stage_logic.h"
    )
    if "static inline" not in cell_stage_h or "cell_config_stage_nested_owner" not in cell_stage_h:
        fail("cell_config_stage_nested_owner must be static inline in private header")
    if (REPO_ROOT / "ports" / "esp-idf" / "src" / "cell_config_stage_logic.c").is_file():
        fail("cell_config_stage_logic.c must be removed (header-only static inline)")
    # Failure atomicity: stage to temps, commit only on success (no out poison).
    if "outer_tmp" not in cell_stage_h or "owner_tmp" not in cell_stage_h:
        fail("cell_config_stage must stage into temps before commit")
    if "*out_outer_local = outer_tmp" not in cell_stage_h:
        fail("cell_config_stage must commit outer_tmp only after validation")
    owner_stage_c = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_config_stage_logic.c"
    )
    owner_stage_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "owner_config_stage_logic.h"
    )
    if "NINLIL_ESP_IDF_INTERNAL" not in owner_stage_h:
        fail("owner_config_stage must use NINLIL_ESP_IDF_INTERNAL (non-DEFAULT export)")
    if "local_tmp" not in owner_stage_c or "hdr_tmp" not in owner_stage_c:
        fail("owner_config_stage must stage into temps before commit")
    if "(owner_storage == NULL) != (owner_storage_size == 0u)" not in owner_stage_c:
        fail("owner_config_stage must closed-reject NULL/size storage contradictions")
    if "pointer_ranges_overlap" not in owner_stage_c:
        fail("owner_config_stage must reject out/storage alias via pointer_range helper")
    internal_h = read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "ninlil_esp_idf_internal.h"
    )
    if "visibility" not in internal_h or "hidden" not in internal_h:
        fail("ninlil_esp_idf_internal.h must define portable hidden visibility")
    # Official ELF gates must be wired into esp-idf.yml (objdump frame + readelf).
    if "esp_idf_app_main_frame_gate.py" not in authority_text:
        fail("esp-idf CI must run app_main frame gate")
    if "xtensa-esp32s3-elf-objdump" not in authority_text:
        fail("esp-idf CI frame gate must use xtensa-esp32s3-elf-objdump explicitly")
    if "esp_idf_private_symbol_gate.py" not in authority_text:
        fail("esp-idf CI must run private symbol / readelf gate")
    if "xtensa-esp32s3-elf-readelf" not in authority_text:
        fail("esp-idf CI symbol gate must use xtensa-esp32s3-elf-readelf explicitly")
    frame_gate = read_text(REPO_ROOT / "tools" / "esp_idf_app_main_frame_gate.py")
    if "false-green" not in frame_gate and "false_green" not in frame_gate:
        fail("frame gate must refuse false-green when objdump missing")
    if "SAFE_MARGIN_BYTES" not in frame_gate:
        fail("frame gate must assert a safety margin")
    sym_gate = read_text(REPO_ROOT / "tools" / "esp_idf_private_symbol_gate.py")
    if "GLOBAL" not in sym_gate or "DEFAULT" not in sym_gate:
        fail("private symbol gate must reject GLOBAL DEFAULT")
    if "owner_config_stage" not in sym_gate:
        fail("private symbol gate must cover owner_config_stage")

    for mirror in PIN_MIRRORS:
        if pin not in read_text(mirror):
            fail(f"{mirror.relative_to(REPO_ROOT)} missing pin {pin}")

    smoke = read_text(SMOKE_APP)
    if "EXTRA_COMPONENT_DIRS" not in smoke:
        fail("smoke_app missing EXTRA_COMPONENT_DIRS")
    smoke_main = read_text(SMOKE_MAIN)
    for needle in (
        "ninlil_esp_idf/clock.h",
        "ninlil_esp_idf/entropy.h",
        "ninlil_esp_idf/execution.h",
        "ninlil_esp_idf/owner_task_storage.h",
        "ninlil_esp_idf/cell_agent_storage.h",
        "ninlil_esp_idf/loopback_tx_permit.h",
        "NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG",
        "ninlil_esp_idf_entropy_shutdown",
        "ninlil_esp_idf_clock_shutdown",
        "ninlil_esp_idf_loopback_tx_permit",
        "SELFTEST",
        "producer_task",
        "post_tick_from_isr",
        "DOUBLE_STOP",
        "stack_hwm_bytes",
        "ESP_TIMER_ISR",
        "acquire_tx_gate_lease",
        "LEASE_STALE",
        "max_leases",
        "event_group_null",
        "double_release_not_stale",
        "snapshot_borrowers_not_2",
        "shutdown_not_busy_two_leases",
        "forged_release_not_stale",
        "tx_gate_borrowers",
        "owner_init_forward_ext",
        "retired s_standalone_owner",
        "ninlil_port/esp_storage.h",
        "ninlil_port/esp_storage_flash.h",
        "ninlil_port_esp_storage_flash_bind",
        "ninlil_port_esp_storage_flash_unbind",
        "NINLIL_STORAGE_COMMIT_UNKNOWN",
        "smoke_storage_commit_unknown",
    ):
        if needle not in smoke_main:
            fail(f"smoke_app must include/use {needle!r}")
    # Post-shutdown full memset of retired standalone owner is forbidden
    # (destroys lifecycle evidence). Pre-init zero remains allowed.
    post_shutdown_wipe = re.search(
        r"owner_task_shutdown\(&s_standalone_owner\).*?"
        r"memset\(&s_standalone_owner",
        smoke_main,
        re.DOTALL,
    )
    if post_shutdown_wipe:
        fail("smoke must not memset retired s_standalone_owner after shutdown")

    # Host tests must assert failure-path output immutability for both helpers.
    if "outer_poison" not in host_test or "local_poison" not in host_test:
        fail("owner_cell_agent_logic_test must poison outs for atomicity checks")
    if "closed reject" not in host_test:
        fail("host owner/cell tests must cover storage NULL/size closed reject")
    if "failure atomicity" not in host_test and "Failure-path output" not in host_test:
        fail("host tests must document/cover failure atomicity for stage helpers")

    sdkconfig = read_text(SMOKE_SDKCONFIG)
    for needle in (
        "CONFIG_SPIRAM=y",
        'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="../partitions/ninlil_storage.csv"',
        "CONFIG_WL_SECTOR_SIZE_4096=y",
        "CONFIG_FREERTOS_UNICORE=n",
        "CONFIG_FREERTOS_CHECK_PORT_CRITICAL_COMPLIANCE=y",
        "CONFIG_ESP_TIMER_SUPPORTS_ISR_DISPATCH_METHOD=y",
    ):
        if needle not in sdkconfig:
            fail(f"smoke sdkconfig missing {needle!r}")
    read_text(PARTITION_CSV)
    read_text(HIL_MAIN)

    print(
        "esp_idf_component_packaging_gate OK: "
        f"pin={pin} pure={len(pure_sources)} backend={len(backend_sources)} "
        f"storage_target={len(storage_target)}"
    )


def self_test() -> None:
    if not VERSION_RE.match("v5.5.3") or VERSION_RE.match("release-v5.1"):
        fail("self-test VERSION_RE")
    sample = "    ports/esp-idf/src/clock_logic.c\n"
    if authority_sources(sample) != ["ports/esp-idf/src/clock_logic.c"]:
        fail("self-test source parse")
    recursive = """set(MODEL
    ports/esp-idf/storage/model/a.c
    ports/esp-idf/storage/model/b.c
)
set(TARGET
    ${MODEL}
    ports/esp-idf/storage/esp/media.c
)
"""
    if list_sources_in_var(recursive, "TARGET") != [
        "ports/esp-idf/storage/model/a.c",
        "ports/esp-idf/storage/model/b.c",
        "ports/esp-idf/storage/esp/media.c",
    ]:
        fail("self-test recursive source expansion")

    # Never write ROOT workflow/script — in-memory mutations only.
    st = CI_WORKFLOW.stat()
    original = CI_WORKFLOW.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()
    meta_before = (
        getattr(st, "st_ino", None),
        st.st_size,
        st.st_mode,
        getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)),
        getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000)),
        original_hash,
    )
    script_original = ESP_IDF_DOCKER_SCRIPT.read_text(encoding="utf-8")
    script_meta_before = (
        ESP_IDF_DOCKER_SCRIPT.stat().st_size,
        hashlib.sha256(script_original.encode("utf-8")).hexdigest(),
    )

    check()
    assert_esp_idf_docker_run_authority(original, script_original)

    def reject_ci(label: str, mutated: str, script: str | None = None) -> None:
        if mutated == original and (script is None or script == script_original):
            fail(f"self-test CI mutation produced no change: {label}")
        try:
            assert_esp_idf_docker_run_authority(
                mutated, script_original if script is None else script
            )
        except SystemExit:
            return
        fail(f"self-test CI mutation was accepted: {label}")

    def reject_script(label: str, mutated_script: str) -> None:
        if mutated_script == script_original:
            fail(f"self-test script mutation produced no change: {label}")
        try:
            assert_esp_idf_docker_run_authority(original, mutated_script)
        except SystemExit:
            return
        fail(f"self-test script mutation was accepted: {label}")

    # Script image / platform authority (mutate docker run IMAGE argv only).
    docker_image_argv = f'  "{ESP_IDF_IMMUTABLE_IMAGE}" \\\n'
    if docker_image_argv not in script_original:
        fail("self-test cannot locate docker run IMAGE argv line in launcher")
    reject_script(
        "tag-only image",
        script_original.replace(
            docker_image_argv,
            '  "docker.io/espressif/idf:v5.5.3" \\\n',
            1,
        ),
    )
    reject_script(
        "floating latest tag",
        script_original.replace(
            docker_image_argv,
            '  "docker.io/espressif/idf:latest" \\\n',
            1,
        ),
    )
    reject_script(
        "wrong digest",
        script_original.replace(
            docker_image_argv,
            '  "docker.io/espressif/idf@sha256:' + ("0" * 64) + '" \\\n',
            1,
        ),
    )
    reject_script(
        "arm64 platform",
        script_original.replace(
            f"--platform {ESP_IDF_PLATFORM}",
            "--platform linux/arm64",
            1,
        ),
    )
    reject_script(
        "extra alternate docker run in script",
        script_original.replace(
            "docker run --rm --interactive",
            "docker run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n"
            "docker run --rm --interactive",
            1,
        ),
    )

    # Workflow must not embed docker; only exact launcher invoke.
    reject_ci(
        "extra inline docker run in workflow",
        original
        + "\n      - run: docker run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n",
    )
    reject_ci(
        r'unicode \u0072un extra docker step',
        original
        + '\n      - "\\u0072un": docker run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n',
    )
    reject_ci(
        "expand_aliases alias d=do''cker floating",
        original
        + "\n      - run: |\n"
        + "          shopt -s expand_aliases\n"
        + "          alias d=do''cker\n"
        + "          d run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n",
    )
    reject_ci(
        "env BAD containing docker run latest plus run",
        original
        + "\n      - name: bad\n"
        + "        env:\n"
        + "          BAD: docker run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n"
        + "        run: echo hi\n",
    )
    reject_ci(
        "bash -c docker run",
        original
        + "\n      - run: bash -c 'docker run --rm docker.io/espressif/idf:latest true'\n",
    )
    reject_ci(
        "eval docker",
        original + "\n      - run: eval docker run --rm docker.io/espressif/idf:latest true\n",
    )
    reject_ci(
        "quoted key run docker",
        original
        + '\n      - "run": docker run --rm --platform linux/arm64 docker.io/espressif/idf:latest true\n',
    )
    # Locate current sole-launcher run line for mutations.
    launcher_line = None
    for line in original.splitlines():
        if "tools/esp_idf_ci_docker_run.sh" in line and "bash" in line:
            launcher_line = line.strip().lstrip("- ").removeprefix("run:").strip()
            break
    if not launcher_line:
        fail("self-test could not locate sole launcher run line in workflow")
    reject_ci(
        "remove sole launcher invoke",
        original.replace(launcher_line, "echo no-docker", 1),
    )
    reject_ci(
        "duplicate launcher invoke",
        original + f"\n      - run: {launcher_line}\n",
    )
    # GHA expression must not appear as executable shell inside the launcher.
    reject_script(
        "GHA expression as pin assignment",
        script_original.replace(
            'pin="$1"',
            'pin="${{ steps.pin.outputs.version }}"',
            1,
        ),
    )

    # Executable script contract (workflow-equivalent argv path; dry-run).
    import subprocess

    def run_launcher(args: list[str], env_extra: dict[str, str] | None = None) -> int:
        env = dict(**{k: v for k, v in __import__("os").environ.items()})
        env["NINLIL_ESP_CI_DRY_RUN"] = "1"
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            ["bash", str(ESP_IDF_DOCKER_SCRIPT), *args],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        return proc.returncode

    if run_launcher(["v5.5.3"]) != 0:
        fail("self-test positive dry-run with argv pin v5.5.3 must PASS")
    if run_launcher([], env_extra={"ESP_IDF_PIN": "v5.5.3"}) != 0:
        fail("self-test positive dry-run with ESP_IDF_PIN env must PASS")
    if run_launcher([]) == 0:
        fail("self-test negative missing pin must FAIL")
    if run_launcher(["v9.9.9"]) == 0:
        fail("self-test negative wrong pin must FAIL")
    if run_launcher(["latest"]) == 0:
        fail("self-test negative non-semver pin must FAIL")

    st2 = CI_WORKFLOW.stat()
    after = CI_WORKFLOW.read_text(encoding="utf-8")
    meta_after = (
        getattr(st2, "st_ino", None),
        st2.st_size,
        st2.st_mode,
        getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1_000_000_000)),
        getattr(st2, "st_ctime_ns", int(st2.st_ctime * 1_000_000_000)),
        hashlib.sha256(after.encode("utf-8")).hexdigest(),
    )
    if meta_after != meta_before or after != original:
        fail("self-test mutated CI workflow source metadata/bytes")
    script_after = ESP_IDF_DOCKER_SCRIPT.read_text(encoding="utf-8")
    if (
        ESP_IDF_DOCKER_SCRIPT.stat().st_size,
        hashlib.sha256(script_after.encode("utf-8")).hexdigest(),
    ) != script_meta_before or script_after != script_original:
        fail("self-test mutated docker launcher script metadata/bytes")
    check()
    print("esp_idf_component_packaging_gate self-test OK")



def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print("usage: esp_idf_component_packaging_gate.py check|self-test", file=sys.stderr)
        return 2
    if argv[1] == "check":
        check()
    else:
        self_test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
