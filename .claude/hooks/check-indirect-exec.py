#!/usr/bin/env python3
"""PreToolUse hook: detect indirect command execution via AST analysis.

Parses Bash commands using bashlex and inspects the AST to find patterns
where one command can indirectly execute another (e.g., find -exec, xargs,
eval, command substitution in arguments, piped shell execution).

When a dangerous pattern is detected, the hook returns permissionDecision: "ask"
so the user is prompted for confirmation, even if the base command is auto-allowed.
"""

import json
import os
import sys

import bashlex

# Project root: derived from this script's location (.claude/hooks/ → ../..)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.realpath(os.path.join(_SCRIPT_DIR, "..", ".."))

# Commands that are inherently command launchers
LAUNCHER_COMMANDS = frozenset(
    {
        "xargs",
        "parallel",
        "nohup",
        "watch",
        "eval",
        "exec",
        "source",
        "env",
    }
)

# Commands with specific flags that enable indirect execution
DANGEROUS_FLAG_PREFIXES = {
    "find": ["-exec", "-execdir", "-ok", "-okdir", "-delete"],
    "tar": ["--checkpoint-action", "--to-command"],
}

# Script interpreters with inline execution flags
SCRIPT_EXEC_FLAGS = {
    "python": {"-c"},
    "python3": {"-c"},
    "perl": {"-e", "-E"},
    "ruby": {"-e"},
    "node": {"-e", "--eval"},
    "bash": {"-c"},
    "sh": {"-c"},
    "zsh": {"-c"},
}

# Commands that, when receiving piped input to sh/bash, are dangerous
# e.g., curl ... | sh
PIPE_TO_SHELL = frozenset({"sh", "bash", "zsh"})
DOWNLOAD_COMMANDS = frozenset({"curl", "wget"})


def basename(cmd):
    """Extract command basename from a potentially full path."""
    return cmd.rsplit("/", 1)[-1]


def extract_command_nodes(node, results=None):
    """Recursively walk the AST and collect all command nodes."""
    if results is None:
        results = []

    kind = node.kind

    if kind == "command":
        results.append(node)
    elif kind == "commandsubstitution":
        # $(...) — recurse into the inner command
        if hasattr(node, "command") and node.command:
            extract_command_nodes(node.command, results)

    # Generic child traversal
    for attr in ("parts", "list"):
        children = getattr(node, attr, None)
        if children and isinstance(children, list):
            for child in children:
                if hasattr(child, "kind"):
                    extract_command_nodes(child, results)

    return results


def get_words(node):
    """Extract word tokens from a command node."""
    words = []
    has_command_substitution = False
    for part in node.parts:
        if part.kind == "word":
            words.append(part.word)
        elif part.kind == "assignment":
            # e.g., VAR=value cmd
            words.append(part.word)
        elif part.kind == "commandsubstitution":
            has_command_substitution = True
            words.append("$(...)")
        elif part.kind == "parameter":
            words.append("${...}")
    return words, has_command_substitution


def check_single_command(words, has_cmd_substitution):
    """Check a single command's word list for dangerous patterns.

    Returns a reason string if dangerous, None otherwise.
    """
    if not words:
        return None

    cmd = basename(words[0])

    # 1. Command is itself a launcher
    if cmd in LAUNCHER_COMMANDS:
        return f"'{cmd}' can execute arbitrary commands"

    # 2. Dangerous flags on specific commands
    if cmd in DANGEROUS_FLAG_PREFIXES:
        prefixes = DANGEROUS_FLAG_PREFIXES[cmd]
        for word in words[1:]:
            for prefix in prefixes:
                if word == prefix or word.startswith(prefix + "="):
                    return f"'{cmd}' with '{word}' enables indirect execution"

    # 3. Script interpreter with inline execution
    if cmd in SCRIPT_EXEC_FLAGS:
        flags = SCRIPT_EXEC_FLAGS[cmd]
        for word in words[1:]:
            if word in flags:
                return f"'{cmd} {word}' executes inline script"

    # 4. awk/gawk with system() call
    if cmd in ("awk", "gawk", "mawk", "nawk"):
        for word in words[1:]:
            if "system(" in word or "system (" in word:
                return f"'{cmd}' with system() enables command execution"

    return None


def check_pipeline_for_pipe_to_shell(trees):
    """Check for download | shell patterns across pipelines."""
    reasons = []
    for tree in trees:
        if tree.kind == "pipeline":
            commands_in_pipe = []
            for part in tree.parts:
                if part.kind == "command":
                    words, _ = get_words(part)
                    if words:
                        commands_in_pipe.append(basename(words[0]))
            # Check if a download command pipes into a shell
            for i, cmd in enumerate(commands_in_pipe[:-1]):
                if cmd in DOWNLOAD_COMMANDS:
                    next_cmd = commands_in_pipe[i + 1]
                    if next_cmd in PIPE_TO_SHELL:
                        reasons.append(
                            f"'{cmd}' piped to '{next_cmd}' — remote code execution"
                        )
    return reasons


def check_cd_target(words, cwd):
    """Check if a cd command navigates outside the project root.

    Returns a reason string if the target is outside PROJECT_ROOT, None otherwise.
    """
    if not words or basename(words[0]) != "cd":
        return None

    if len(words) < 2:
        # bare 'cd' goes to $HOME — outside project
        return "'cd' without arguments navigates to $HOME (outside project)"

    target = words[1]

    # Unresolvable targets (variables, command substitution)
    if target.startswith("$") or target in ("$(...)", "${...}"):
        return f"'cd {target}' — target cannot be statically resolved"

    # Expand tilde before resolving
    target = os.path.expanduser(target)

    # Resolve the target path
    if os.path.isabs(target):
        resolved = os.path.realpath(target)
    else:
        resolved = os.path.realpath(os.path.join(cwd, target))

    # Check if resolved path is under PROJECT_ROOT
    # Use trailing separator to prevent prefix match on sibling directories
    # e.g., /home/user/project-other should not match /home/user/project
    if not (resolved == PROJECT_ROOT or resolved.startswith(PROJECT_ROOT + os.sep)):
        return f"'cd {target}' resolves to '{resolved}' (outside project root)"

    return None


def analyze(command_str, cwd):
    """Parse and analyze a command string for indirect execution patterns."""
    reasons = []

    try:
        trees = bashlex.parse(command_str)
    except bashlex.errors.ParsingError:
        # Unparseable command → err on the side of caution
        return ["Command contains syntax that cannot be statically analyzed"]

    # Check individual commands
    for tree in trees:
        for cmd_node in extract_command_nodes(tree):
            words, has_cmd_sub = get_words(cmd_node)

            # Check cd target
            cd_reason = check_cd_target(words, cwd)
            if cd_reason:
                reasons.append(cd_reason)

            # Check indirect execution
            reason = check_single_command(words, has_cmd_sub)
            if reason:
                reasons.append(reason)

    # Check pipeline patterns (download | shell)
    for tree in trees:
        reasons.extend(check_pipeline_for_pipe_to_shell(tree if isinstance(tree, list) else [tree]))

    return reasons


def main():
    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command.strip():
        sys.exit(0)

    cwd = hook_input.get("cwd", PROJECT_ROOT)
    reasons = analyze(command, cwd)

    if reasons:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "Indirect execution detected:\n"
                + "\n".join(f"  - {r}" for r in reasons),
            }
        }
        json.dump(output, sys.stdout)

    sys.exit(0)


if __name__ == "__main__":
    main()
