# 🔐 AI-Driven Next-Generation Firewall (NGFW)

## Architecture, Flow & Intelligence Overview

---

## 📍 High-Level System View

This NGFW is designed as an **inline enforcement system**, operating directly on live traffic paths.

```
[ Client / Endpoint ]
        |
     (Router)
        |
      TAP0
        |
+-------------------+
|   NGFW ENGINE     |
|-------------------|
| Forwarder (L2–L4) |
| Flow Tracker      |
| ML Classifier     |
| Anomaly Engine    |
| SOAR Controller   |
+-------------------+
        |
      TAP1
        |
   (Core Switch)
        |
   [ Servers / DC ]
```

---

## 🔁 Inline Packet Processing Flow

```mermaid
flowchart LR
    A[Packet arrives at TAP0] --> B[Ethernet Parsing]
    B --> C{IPv4?}
    C -- No --> F[Forward packet]
    C -- Yes --> D{TCP/UDP?}
    D -- No --> F
    D -- Yes --> E[Session Lookup / Create]
    E --> G[Update Flow State]
    G --> H{Packet count < 10?}
    H -- Yes --> F
    H -- No --> I[Trigger Classification]
    I --> J{Decision}
    J -- Allow --> F
    J -- Block --> K[Drop / RST]
```

---

## 🧠 Session Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NEW
    NEW --> SYN_SENT
    SYN_SENT --> ESTABLISHED
    ESTABLISHED --> FIN_WAIT
    FIN_WAIT --> CLOSED
    ESTABLISHED --> CLOSED_RST
```

---

## 📦 First-10-Packet Decision Logic

```mermaid
flowchart TD
    A[New Flow Detected] --> B[Allow packets 1–10]
    B --> C[Capture metadata]
    C --> D{Plaintext?}
    D -- Yes --> E[L7 Feature Extraction]
    D -- No --> F[Encrypted / L4 Path]
    E --> G[ML Classifier]
    F --> G
    G --> H[Decision Stored]
    H --> I[Packet 11+ Enforced]
```

---

## 📊 Feature Extraction (Examples)

| Category | Features |
|--------|----------|
| Timing | Duration, inter-arrival |
| Volume | Bytes / packets |
| TCP | Window, seq numbers |
| Network | TTL asymmetry |
| Heuristics | Small-packet flags |

---

## 🔐 Encrypted Traffic Intelligence

```mermaid
flowchart TD
    A[TLS ClientHello] --> B[JA3 Fingerprint]
    B --> C[SNI Extraction]
    C --> D[Threat Intel Lookup]
    D --> E[Risk Score]
```

---

## 🧬 Federated Learning Topology

```mermaid
flowchart LR
    A[NGFW Instance 1] --> C[Federated Aggregator]
    B[NGFW Instance 2] --> C
    C --> D[Global Model]
    D --> A
    D --> B
```

---

## 🤖 SOAR Automation

```mermaid
flowchart TD
    A[High Risk] --> B[Decision Engine]
    B --> C{Action}
    C -- Block --> D[iptable DROP]
    C -- Quarantine --> E[LOG + DROP]
    C -- Alert --> F[Email / Ticket]
```

---

## 🛡 IDS + ML Hybrid

```mermaid
flowchart LR
    A[Traffic] --> B[Suricata IDS]
    A --> C[ML Engine]
    B --> D{Signature Match}
    D -- Yes --> E[Override Block]
    D -- No --> C
```

---

## 📊 Dashboard Data Flow

```mermaid
flowchart TD
    A[sessions.db] --> B[Dashboard API]
    B --> C[Streamlit UI]
```

---

## 🧪 Realism & Validation

✔ Inline enforcement  
✔ GNS3-based realistic topology  
✔ SOAR tested under load  
✔ ~1.2 Gbps throughput observed  

---

## 🧠 Design Philosophy

> If it cannot run inline on real traffic, it is not a firewall.
