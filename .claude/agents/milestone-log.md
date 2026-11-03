---
name: milestone-log
description: Generate a detailed milestone summary markdown file in milestone-logs/ for this PQC gateway project. Use this skill whenever a milestone (M0–M8) has just been completed, or when the user says "log this milestone", "write the milestone summary", "document M1" (or any M0–M8), "generate milestone log", or similar. The skill collects git history, test results, and implementation details automatically and writes a structured report to milestone-logs/MX-name.md that is useful for the project report.
---

# Milestone Log Skill

Generate a thorough milestone summary in `milestone-logs/` that captures everything needed for the project report: what was built, why each decision was made, test evidence, and what an examiner should know.

## Step 1: Identify the milestone

Determine which milestone to log:
- If the user named it explicitly (e.g. "log M1"), use that.
- Otherwise read `PROGRESS.md` and use the most recently completed milestone (status = DONE with the highest ID).

Set these variables mentally:
- `MILESTONE_ID` — e.g. `M1`
- `MILESTONE_NAME` — e.g. `crypto-layer` (derive from the branch name or PROGRESS.md notes)
- `OUTPUT_FILE` — `milestone-logs/{MILESTONE_ID}-{MILESTONE_NAME}.md`

## Step 2: Gather raw information (run all at once)

Run these shell commands to collect facts — don't skip any:

```bash
# 1. PROGRESS.md content
cat PROGRESS.md

# 2. Git log for the milestone branch (commits not on main)
git log main..HEAD --oneline 2>/dev/null || git log --oneline -20

# 3. Files changed in this milestone
git diff main..HEAD --name-status 2>/dev/null || git diff HEAD~5..HEAD --name-status

# 4. Full diff stat
git diff main..HEAD --stat 2>/dev/null || git diff HEAD~5..HEAD --stat

# 5. Run the test suite and capture output
.venv/bin/pytest --tb=short -q 2>&1 | tail -40

# 6. List all new source files added this milestone
git diff main..HEAD --name-only --diff-filter=A 2>/dev/null | grep -E '\.(py|toml|md)$'

# 7. Current branch name
git branch --show-current

# 8. Today's date
date "+%Y-%m-%d"
```

Also read the key source files that were created or significantly changed in this milestone so you can describe the design accurately. For M1 that means the crypto interfaces, providers, hybrid combiner, and registry. Use `git diff main..HEAD -- <file>` to read each new file's content efficiently.

## Step 3: Write the milestone log

Write to `OUTPUT_FILE`. Use this exact structure:

---

```markdown
# {MILESTONE_ID}: {Full milestone name from CLAUDE.md}

**Date completed:** {today}  
**Branch:** {branch name}  
**Commits:** {N commits}  
**Tests:** {X passed, 0 failed}

---

## What was implemented

List every module/file created or substantially changed, with one sentence on its role. Group logically (e.g. "Crypto interfaces", "Providers", "Tests"). For each group, name the files and their purpose. Be specific — name classes, functions, and constants where they matter.

## Why it was implemented this way

This is the most important section for the report. For each significant design decision, explain the reasoning. Draw from:
- CLAUDE.md (which mandates specific choices — cite the section)
- Docstrings in the code
- The PROGRESS.md decisions table
- Standard references (FIPS 203/204, liboqs docs)

Cover at minimum:
- Why abstract interfaces rather than direct imports (protocol isolation, agility)
- Why runtime algorithm discovery rather than hardcoded names (liboqs version portability)
- The OI-1 length-validation guard and the vulnerability it prevents (GHSA-w696-4vrr-x6x3)
- The wire format chosen for hybrid KEM/Signature (u16-length-prefix, fixed suite order)
- Why HybridSignature is NOT a standardised composite (and what it is instead)
- ECDSA-P256 raw r||s format choice (§15 item 6)
- ML-DSA empty context string (FIPS 204 allows it; we document it)

## Key results and test evidence

### Test summary
Paste or summarise the pytest output: total collected, passed, failed, any skipped with reason.

### Size assertions (FIPS 203/204 compliance)
List the algorithms verified and their confirmed sizes (pk, ct/sig). State clearly that the installed liboqs agrees with FIPS values.

### Round-trip verification
State that KEM (keygen→encaps→decaps) and Signature (keygen→sign→verify) round-trips pass for every algorithm, including hybrid combiners.

### Security regression coverage
List the OI-1 regression tests and what they verify (short pk, empty pk, empty ct — each raises ValueError before reaching liboqs).

## Open issues resolved this milestone

List items from PROGRESS.md that were OI (open issues) and are now closed. For each: what the issue was and how it was resolved.

## Known limitations relevant to this milestone

List any limitations from CLAUDE.md §1 or PROGRESS.md that apply to what was built here. For M1 this includes:
- Algorithm agility covers only the four interfaces defined; no claim about future algorithms (CLAUDE.md §1 limitation 4)
- FN-DSA and HQC labelled experimental and only included if the installed library exposes them (limitation 5)

## What an examiner should know

Write 3–6 bullet points covering the things that are non-obvious but security-critical. These are the points that matter for a viva or report defence. Examples:
- The separation between interface and implementation (why it matters for agility)
- How the hybrid KEM concatenates shared secrets and why order is fixed
- Why both signatures in HybridSignature must independently verify
- How the OI-1 guard prevents a class of memory-safety issues in the C library
- Where randomness comes from (OS CSPRNG via liboqs and cryptography package — no seeding)

---
*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
```

---

## Step 4: Write the file

Write the completed markdown to `milestone-logs/{MILESTONE_ID}-{MILESTONE_NAME}.md`. Create the `milestone-logs/` directory if it doesn't exist.

## Step 5: Report back

Tell the user:
- The file path written
- Test count summary (X passed)
- One sentence on anything notable or worth their attention before they use the log for the report

Do not print the full file contents in the chat — just the path and summary. The file is there for them to read.
