# Codebase Refactoring Protocol

**Target**: Claude Opus 4.5 in Cursor IDE  
**Mission**: Refactor Rust codebase to meet `.cursor/rules.md` standards.

**Hard Limits**: Files ≤500 lines | Functions ≤50 lines (body, excluding signature/docs) | Zero warnings | Zero meaningful duplication | Zero dead code

---

## Execution Model

- Operate one logical refactor at a time
- Prefer small, reversible diffs
- Use Cursor's native tools (Glob, Read, Grep) instead of shell commands for file discovery
- After every change, run validation commands
- If validation fails → revert and report before continuing

**Validation commands:**
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
cargo machete
```

---

## Phase 1: Scan (Read-Only)

Using Cursor tools, identify:

1. **Oversized files** — Use Glob to find all `.rs` files, Read each, count lines
2. **Oversized functions** — Search for `fn ` patterns, read context to find function boundaries, count body lines
3. **Clippy warnings** — Run: `cargo clippy --all-targets --all-features -- -D warnings`
4. **Dead code** — Look for `#[allow(dead_code)]`, unused items, unreachable branches
5. **Duplication** — Logic repeated ≥5 lines across locations (not test boilerplate)
6. **Complexity smells** — Nesting ≥4, parameters ≥5, match arms ≥5

### Definitions

- **Line count**: All lines in file including blanks and comments
- **Function body**: Lines from opening `{` to closing `}`, excluding signature and doc comments
- **Meaningful duplication**: Identical or near-identical logic (not type-specific boilerplate or test setup)
- **Test code**: `#[cfg(test)]` modules may have relaxed duplication rules for clarity

### Output Format

```
path/to/file.rs
- Lines: N
- Violations:
  - fn foo(): 83 lines (body)
  - Duplicate logic with bar() (~7 lines)
  - Clippy: needless_return
```

**Do not propose fixes yet. End with:** "Phase 1 complete. Approve to proceed to Phase 2?"

---

## Phase 2: Plan (Approval Required)

Produce a ranked task list.

### Priority Order
1. **Critical** — Size limits exceeded, build failures
2. **High** — Duplication, high complexity
3. **Medium** — Dead code, long parameter lists
4. **Low** — Naming, docs, style

### Task Format

Reference by function/struct name (line numbers shift after refactors):

```
path/file.rs::process_request() | Extract validation into validate_request() | Risk: safe
path/file.rs::Config | Move to config.rs (file at 520 lines) | Risk: safe
```

### Risk Levels
- **safe** — Pure extraction, no logic changes
- **moderate** — Restructuring that preserves semantics
- **risky** — Changes near complex logic or public APIs

**End Phase 2 with:** "Approve plan to begin Phase 3?"

**Do not proceed without explicit approval.**

---

## Phase 3: Execute

### Rules
- One task → one diff
- No cascading "while I'm here" changes
- Prefer extraction over rewriting
- Prefer `pub(crate)` helpers over expanding public API
- Test code: `unwrap()`/`expect()` allowed, duplication acceptable for clarity

### Cross-File Refactors

When a refactor spans multiple files (e.g., module extraction):
- Treat all affected files as one atomic unit
- List all files that will be modified before making changes
- All files must pass validation together
- Typical pattern: source file + target module + mod.rs/lib.rs

### Approved Patterns
- Function splitting: `validate_*()`, `prepare_*()`, `execute_*()`, `build_*()`
- Early returns to reduce nesting
- Parameter grouping into structs
- Private helper functions (same file first, then module)
- Module extraction when cohesion improves

### After Each Task

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
cargo machete
```

Report: "Task complete. [file] now at [N] lines. Continuing to next task."

### Recovery Protocol

If validation fails:
1. Report the failure clearly (which command, what error)
2. Undo the change (re-apply previous file content)
3. Mark task as **blocked** with reason
4. Ask: "Task blocked: [reason]. Skip and continue, or stop for guidance?"

---

## Phase 4: Verify (Full Pass)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
cargo machete  # unused dependencies
```

### Checklist

- [ ] All files ≤500 lines
- [ ] All functions ≤50 lines (body)
- [ ] Zero meaningful duplication
- [ ] Zero dead code (no `#[allow(dead_code)]` without justification)
- [ ] Zero warnings
- [ ] All tests passing
- [ ] No public API expansion

---

## Phase 5: Report

```
Metric                     | Before | After | Δ
---------------------------|--------|-------|----
Files > 500 lines          |   X    |   0   | -X
Functions > 50 lines       |   Y    |   0   | -Y
Duplication instances      |   Z    |   0   | -Z
Dead code items            |   W    |   0   | -W
Warnings                   |   V    |   0   | -V
```

**Summary:**
- Files modified: [list]
- Files created: [list]
- Functions extracted: [count]
- Lines removed: [net change]
- Blocked tasks: [list with reasons, if any]

---

## Prohibitions

- No speculative refactors
- No "while I'm here" changes
- No style-only diffs unrelated to current task
- No `unwrap()`/`expect()` in production code
- No public API expansion
- No skipping phases
- No semantic/behavior changes (error messages, log output, and validation order are considered behavior)

---

## Workspace Awareness

This is a multi-crate workspace. When refactoring:

- Process leaf crates before crates that depend on them
- Cross-crate extraction requires updating both crates' imports
- Visibility: prefer `pub(crate)`, use `pub` only for cross-crate APIs
- Check downstream crates compile after changes to shared code

---

## Handling Blocks

If genuinely stuck (conflicting requirements, architectural decision needed):

1. Document the conflict clearly
2. Mark task as **blocked**
3. Continue with unblocked tasks
4. Report all blocked items in Phase 5

Do not guess or invent solutions for architectural decisions.

---

## Quick Reference

| Problem | Solution |
|---------|----------|
| File >500 lines | Extract: types.rs, errors.rs, helpers.rs, or split by feature |
| Function >50 lines | Extract: `validate_*()`, `prepare_*()`, `execute_*()`, early returns |
| Duplication | Private helper (same file) → utility module (same crate) → trait (cross-crate) |
| Deep nesting | Early returns, extract conditionals to `is_*()` / `should_*()` |
| Many parameters | Group into config/options struct |
| Complex match | Extract arms to helper functions |

---

## Start

**Begin Phase 1 only.**  
Generate the violation report using Cursor tools.  
Wait for approval before proceeding to Phase 2.
