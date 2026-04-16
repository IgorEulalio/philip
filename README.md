# Philip

**Supply chain attack detector for self-hosted CI/CD runners.**

Philip monitors process-level behavior on self-hosted CI/CD runners, builds behavioral baselines per repository, and uses AI-powered triage to detect supply chain attacks — with minimal false positives.

## How It Works

1. **Monitor** — An agent on the runner host uses Tetragon (eBPF) to observe every process execution, network connection, and file access during CI/CD jobs.

2. **Baseline** — Over time, Philip builds a behavioral profile for each repository: which binaries run, which hosts are contacted, which files are accessed.

3. **Detect** — When a build deviates from baseline (e.g., a dependency tries to exfiltrate secrets to an unknown IP), Philip flags it.

4. **Triage** — Deviations pass through two AI layers before alerting:
   - **L1**: Fast rule-based classifier filters known benign changes (dependency updates, cache rebuilds)
   - **L2**: LLM-powered deep analysis for suspicious events (severity scoring, MITRE ATT&CK mapping)

5. **Alert** — Only high-confidence findings reach humans via Slack, webhooks, or other integrations.

## Architecture

```
Self-Hosted Runner Host                     Philip Backend (docker-compose)
┌─────────────────────────┐                ┌──────────────────────────────┐
│  Tetragon (eBPF)        │                │  Ingestion API               │
│         │                │                │  Baseline Engine             │
│  Philip Agent           │──────────────▶│  Deviation Scorer            │
│  (event normalizer,     │   job events   │  AI Triage (L1 + L2)        │
│   process tree builder) │                │  Alert Router                │
└─────────────────────────┘                └──────────────────────────────┘
```

## Quick Start

### Prerequisites

- Self-hosted GitHub Actions runner (Linux 5.8+)
- [Tetragon](https://tetragon.io/) installed on the runner host
- Docker + Docker Compose (for the backend)

### 1. Deploy the backend

```bash
cd deploy
docker-compose up -d
```

### 2. Install the agent on your runner host

```bash
make build-agent
sudo cp bin/philip-agent /usr/local/bin/
sudo cp deploy/systemd/philip-agent.service /etc/systemd/system/
sudo systemctl enable --now philip-agent
```

### 3. Add the GitHub Action to your workflow

```yaml
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: philip-ai/philip-action@v1
        with:
          mode: monitor  # or "enforce" to fail on detection
      - uses: actions/checkout@v4
      - run: npm install
      - run: npm run build
```

## Detection Logic

Philip's detection system is the core of the project. For a detailed explanation of how every layer works — baselines, scoring, MITRE ATT&CK mapping, attack chain detection, and the L1/L2 triage pipeline — see **[Detection Logic](docs/detection-logic.md)**.

## Project Structure

```
philip/
  agent/          # Agent binary (runs on runner host)
  backend/        # Backend service (baseline, detection, triage, alerting)
  action/         # GitHub Action
  proto/          # Protobuf definitions
  deploy/         # Deployment configs (docker-compose, systemd)
  docs/           # Documentation
```

## Tech Stack

- **Agent**: Go + Tetragon gRPC client
- **Backend**: Go + PostgreSQL + TimescaleDB
- **AI Triage**: Pluggable LLM interface (OpenAI)
- **Integration**: GitHub Actions

## License

Apache License 2.0 — see [LICENSE](LICENSE).
