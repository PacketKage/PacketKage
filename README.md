<p align="center">
  <img src="assets/Logo.png" alt="PacketKage" width="480" />
</p>

[![CI](https://github.com/besafewithsamy/PacketKage/actions/workflows/ci.yml/badge.svg)](https://github.com/besafewithsamy/PacketKage/actions/workflows/ci.yml)  

<img src="https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white"/>  <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" /> <img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" /> <img src="https://img.shields.io/badge/fastapi-109989?style=for-the-badge&logo=FASTAPI&logoColor=white" />

**Network traffic analysis and investigation, built around understanding what happened.**

PacketKage turns raw network traffic into a clear picture of network activity. Instead of forcing you to work through thousands of packets to understand an incident, it reconstructs the traffic into flows, hosts, protocols, behaviors, events, and alerts  while keeping the underlying packets available as evidence.

> Here is what happened. Let me show you the network evidence behind it.

```text
Packets → Flows → Hosts → Behaviors → Events → Investigation
````

## Overview

![Dashboard overview](assets/pic1.png)

## What PacketKage Does

### Traffic Investigation

* Live interface capture with BPF filtering and auto-stop
* Reconstructs bidirectional TCP and UDP flows
* IPv4 and IPv6 traffic with correct internal/external direction classification
* Tracks packets, bytes, duration, and direction
* Detects retransmissions, resets, and connection failures
* Provides packet-level evidence for investigations
* Delete captures (and all derived analysis data + the stored PCAP) via `DELETE /api/captures/{id}` or the Capture page — blocked with an actionable error while an analysis is still running

### Host & Protocol Analysis

* Builds profiles for observed hosts
* Identifies services, ports, and communication relationships
* Reconstructs DNS transactions (A and AAAA records)
* Analyzes HTTP requests and responses
* Extracts TLS sessions with SNI and negotiated version
* Labels QUIC (HTTP/3) traffic on UDP 443
* Extracts plaintext protocol banners (SSH, SMTP, FTP)
* Decodes DHCP conversations (DORA) with client hostnames
* Provides protocol-level behavioral statistics

### Suspicious Activity Detection

PacketKage uses deterministic and explainable rules rather than relying on black-box machine learning.

Current detections include:

* Port scanning
* C2-style beaconing
* Low-and-slow beaconing (long-interval periodic check-ins)
* DNS tunneling indicators
* DGA (algorithmically-generated domain) indicators
* NXDOMAIN bursts
* ARP spoofing (IP claimed by multiple MACs)
* Lateral movement (internal fan-out on admin ports)
* Data exfiltration (volume + first-contact correlation)
* Suspicious ports
* Excessive connection failures
* Direct-IP connections without DNS
* Unusually high outbound traffic
* Suspicious user agents

Each alert provides a score, severity, explanation, detection reasons, supporting evidence, and related flows.

Related alerts are also correlated into **incidents**  per-host groups of alerts that belong to one campaign  with a plain-English story of what happened.

### Timeline, Graph & Replay

PacketKage turns network activity into an investigation timeline that can be filtered by host, protocol, event type, severity, and time.

It also provides:

* Network relationship graphs
* Chronological event timelines
* Incident replay
* Flow and packet drill-down

### Evidence Graph 2.0


![Graph overview](assets/graph.png)

The Graph page is built on a materialized, provenance-carrying relationship graph (versioned API `/api/graph/v2`, alongside the legacy graph). Every edge carries a provenance class:

* **observed** : directly seen in packet-derived artifacts (flows, DNS, TLS, HTTP)
* **correlated** : derived by deterministic correlation (incidents → alerts)
* **enriched** : static enrichment, clearly labeled as such (MITRE technique mapping)

Nodes are stable IDs (`host:{ip}`, `domain:{name}`, `service:{ip}:{port}`, `alert:{id}`, `incident:{source_ip}`, `case:{id}`) hydrated from existing tables at query time  no data duplication. Nothing here invents evidence: if an edge has no alert evidence, its explanation is empty; if a technique has no matching rule, it is not shown.

Investigation modes:

* **Investigate**  interactive evidence graph with node and edge drill-down panels
* **Attack Path**  bounded path extraction between two entities (every hop is an observed/correlated edge; the assembled path is an inference, labeled as such)
* **Blast Radius**  reachability analysis from a host, computed only from observed relationships
* **Timeline**  chronological view of the graph events
* **Evidence Chain**  walks Conclusion → Detection → Evidence → Flows → PCAP reference for every displayed claim

Suspicious edges explain themselves by aggregating the real alerts that touch a pair  scores and explanations are deterministic, not invented. Detections are enriched with either official MITRE ATT&CK technique mappings or clearly labeled PacketKage internal classifications; internal classifications never render as ATT&CK IDs.

### Cases & Investigation Workflow

* Group related captures into a **case**  one incident, one story
* Merged chronological timeline across every capture in the case
* Case-level statistics: total packets, alerts, correlated incidents
* One-click **HTML investigation report** (printable to PDF) with alerts, reasons, evidence, incidents, and timeline highlights
* Alert triage: tag as `confirmed`, `false-positive`, or `escalated`, add analyst notes, and filter out triaged alerts
* Alert flow deep links that jump straight to the packet evidence

### Network Engineering

PacketKage is not limited to security investigations. It also provides network health information including:

* Bandwidth and packet rates
* Top talkers
* TCP health
* DNS health
* Traffic distribution
* Network issues

## Quick Start


### One command with Docker (no prerequisites except Docker)

```bash
docker compose up
```

Then open [http://localhost:8000](http://localhost:8000) the full app (frontend + API) runs in a single container, with analysis data persisted in a named volume.

### Requirements (manual setup)

* Python 3.12+
* Node.js 18+
* npm

### Backend

```bash

cd PacketKage/backend

source .venv/bin/activate

python -m uvicorn app.main:app --reload --port 8000

```

> **Linux — enable live capture (one-time):** live sniffing needs `CAP_NET_RAW`/`CAP_NET_ADMIN`. Grant them to the venv interpreter instead of running the backend as root:
>
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
> ```
>
> Re-run it after recreating the venv. Everything except live capture works without it.

The API will be available at:

[http://localhost:8000](http://localhost:8000)

Interactive API documentation:

[http://localhost:8000/docs](http://localhost:8000/docs)

### Frontend

Open another terminal:

```bash

cd PacketKage/frontend

npm run dev
```

Then open:

[http://localhost:5173](http://localhost:5173)

## Test Data

PacketKage includes a deterministic PCAP generator for development and testing.

From the `backend` directory with the virtual environment activated:

```bash
python ../scripts/generate_test_pcaps.py --out ../test-data/synthetic
```

The generator includes scenarios such as:

* Normal traffic
* Port scanning
* DNS tunneling
* C2-style beaconing
* Low-and-slow beaconing
* TCP connection problems
* ARP spoofing
* Lateral movement
* Data exfiltration
* DGA domains
* IPv6 traffic
* QUIC traffic
* Protocol banners (SSH/SMTP/FTP)
* DHCP lease

## Architecture

PacketKage separates packet parsing from the analysis engine through a normalized internal model.

```text
PCAP
  │
  ▼
Packet Parser
  │
  ├── Scapy
  └── TShark
  │
  ▼
Normalized Packets
  │
  ├── Flow Reconstruction
  ├── Protocol Analysis
  ├── Host Profiling
  └── Behavioral Analysis
          │
          ▼
        Alerts
          │
          ▼
 Timeline / Graph / Replay
          │
          ▼
     Investigation
```

Parser-specific objects do not leave the parser layer. This keeps the analysis engine independent from the underlying packet parser and makes it possible to add additional parsers in the future.

## Project Structure

```text
PacketKage/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── parsers/
│   │   ├── repositories/
│   │   ├── schemas/
│   │   └── services/
│   └── tests/
│
├── frontend/
│   └── src/
│       ├── api/
│       ├── components/
│       ├── pages/
│       └── types/
│
├── scripts/
│   └── generate_test_pcaps.py
│
└── test-data/
```

## Tech Stack

### Backend

* Python
* FastAPI
* SQLAlchemy
* SQLite
* Scapy
* Pydantic

### Frontend

* React
* TypeScript
* Vite
* Tailwind CSS
* Zustand
* TanStack Table
* Cytoscape.js
* Recharts

## Testing

The project is covered by three test layers, all wired into GitHub Actions CI:

**Backend**  157 integration tests (pytest) over the full analysis pipeline, including the evidence graph, retry logic, and rule suites:

```bash
cd backend
source .venv/bin/activate
pytest tests/ -q
```

**Frontend unit tests** (vitest):

```bash
cd frontend
npm test
```

**End-to-end** (Playwright) — boots both servers and drives the real UI:

* **Smoke**: upload → analyze → alerts — the whole product in one path
* **Graph**: edge-type filter toggles, scale tiers, and the evidence graph v2 (provenance, attack path, blast radius, evidence chain)
* **Export**: CSV export of flows, and the empty-filter toast case

Self-contained:

```bash
cd frontend
npx playwright test
```

PacketKage also uses deterministic synthetic PCAPs to make analysis scenarios reproducible during development and testing.

## Live Capture

PacketKage can also record traffic directly from a network interface  no upload needed. On the **Capture** page:

1. Pick a network interface (and optionally a BPF filter, e.g. `tcp port 80`)
2. Press **Start live capture**  a live packet counter and auto-stop countdown appear
3. Press **Stop & analyze** (or let the auto-stop timer fire)

The recorded traffic is saved as a PCAP and flows through the exact same analysis pipeline as an upload  flows, hosts, alerts, timeline, everything.

> Note: live sniffing needs elevated permissions. Run the backend as root, or grant the Python process `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities. Interface listing and all other features work unprivileged.

## Roadmap

* Real-time streaming analysis of live captures
* PCAP analysis caching
* Additional protocol parsers

## Current Status

PacketKage is currently a local, single-user application focused on PCAP-based network investigation and analysis.

The core analysis pipeline, flow reconstruction, protocol analysis, behavioral detection, timeline, graph, replay, and network engineering features are implemented.

## Contributing

PacketKage is an evolving project. Contributions, ideas, bug reports, and improvements are welcome.

If you have an idea that could make network traffic easier to understand or investigate, feel free to open an issue or submit a pull request.


