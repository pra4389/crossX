username : admin

password : crossX@2026




# 💰 CrossX — Money Muling Detection Engine

A **graph-theory-based** web application that detects money muling patterns in fiancial transaction data using cycle detection, smurfing analysis, shell-network tracing, and entropy-based scoring.

---

## 📌 Problem Statement

**Money muling** is one of the fastest-growing methods of financial crime worldwide. Criminals recruit individuals — knowingly or unknowingly — to transfer illegally obtained money through their personal bank accounts. This is done to disguise the origin of illicit funds and make them appear legitimate, a process known as **money laundering**.

### Why is this a critical problem?

- **Scale:** According to Europol and FinCEN, money mule networks facilitate _billions of dollars_ in illicit transactions every year.
- **Recruitment:** Criminals exploit students, job seekers, and immigrants by offering "easy money" or fake employment. Over **90%** of money mule transactions are linked to cybercrime.
- **Detection difficulty:** Traditional rule-based banking systems rely on simple thresholds (e.g., flag any transaction above $10,000). Criminals exploit this by **structuring** transactions just below thresholds and routing money through multiple accounts in complex chains.
- **Victim impact:** Money muling directly enables fraud, ransomware payouts, drug trafficking, and human trafficking. Mules themselves face criminal prosecution, even if unknowingly involved.

### How do money mule networks actually operate?

A typical money muling operation involves **three stages**:

1. **Placement** — Illicit money enters the banking system. Criminals divide large sums into smaller deposits across multiple mule accounts to avoid triggering automatic reporting thresholds (a technique called **smurfing**).

2. **Layering** — The money is moved rapidly through a chain of mule accounts, often across different banks and countries. Each hop makes it harder to trace. Common layering techniques include:
   - **Circular routing:** A → B → C → A (money flows in loops to obscure origin)
   - **Fan-in / Fan-out:** Many accounts funnel into one collection hub, which then distributes to many outgoing accounts
   - **Pass-through relays:** Shell accounts that receive and immediately forward funds, retaining near-zero balance
   - **Decreasing-amount chains:** Each hop deducts a small "commission," e.g., $10,000 → $9,500 → $9,000

3. **Integration** — The laundered money is withdrawn or spent, now appearing to have a legitimate source.

### How was this traditionally detected?

| Traditional Approach | Limitation |
|---------------------|------------|
| Fixed threshold rules (flag tx > $10K) | Easily defeated by structuring deposits just below the threshold |
| Manual investigation by compliance teams | Extremely slow, expensive, and cannot scale to millions of transactions |
| Keyword and blacklist matching | Only catches known bad actors, misses new mule networks entirely |
| Single-transaction analysis | Cannot see multi-hop chains or circular patterns — analyzes each transaction in isolation |

> **The core gap:** Traditional systems look at _individual transactions_ in isolation. They cannot detect patterns that emerge only when you analyze the _network of relationships_ between accounts — cycles, fan structures, relay chains, and timing correlations.

---

## 💡 Our Solution — How CrossX Works

CrossX addresses this gap by modeling all transactions as a **directed graph** (network) and applying **graph-theory algorithms** to detect the structural patterns that money mule networks inevitably create.

### Architecture Overview

```
CSV Upload / Demo Data
        │
        ▼
┌─────────────────────┐
│  Data Validation &  │   Validates schema, cleans encoding,
│  Cleaning           │   normalizes columns
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Graph Construction │   Builds a directed multigraph using NetworkX
│  (NetworkX)         │   Nodes = accounts, Edges = transactions
└────────┬────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│         10-Pattern Detection Engine         │
│                                             │
│  1. Cycle Detection (DFS)                   │
│  2. Fan-In Smurfing (Collection Hubs)       │
│  3. Fan-Out Smurfing (Distribution Hubs)    │
│  4. Shell/Pass-Through Network Detection    │
│  5. Rapid Velocity Analysis                 │
│  6. Layering (Decreasing-Amount Chains)     │
│  7. Structuring (Threshold Avoidance)       │
│  8. Community/SCC Clustering                │
│  9. New Account Burst Detection             │
│  10. Entropy & Amount Consistency Analysis  │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Suspicion Scoring  │   Weighted aggregation → 0–100 score per account
│  Engine (Brain)     │   with false-positive trust multiplier control
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Fraud Ring         │   Groups suspicious accounts into named rings
│  Grouping           │   based on connected cycle/community membership
└────────┬────────────┘
         │
         ▼
┌────────────────────────────────────────┐
│  Output & Visualization               │
│                                        │
│  • Interactive vis.js network graph    │
│  • Risk-scored account table           │
│  • Downloadable JSON report            │
│  • Admin panel with trace & override   │
└────────────────────────────────────────┘
```

### Key Implementation Details

1. **Graph Construction:** Every transaction becomes a directed edge from sender → receiver in a NetworkX `MultiDiGraph`. Attributes include amount, timestamp, and transaction ID. A collapsed `DiGraph` is also built for cycle detection.

2. **Cycle Detection (DFS):** Uses depth-first search to find all directed cycles of length 3–5. Circular fund routing (A → B → C → A) is the most classic money muling signature — in legitimate banking, money almost never flows in a perfect circle back to the originator.

3. **Smurfing Analysis:** Identifies **fan-in hubs** (10+ senders → 1 receiver) and **fan-out hubs** (1 sender → 10+ receivers). Also checks for low amount variance and timing clustering, which indicate coordinated structuring.

4. **Shell Network Detection:** Finds relay/pass-through accounts with near-zero net balance (money in ≈ money out), low degree, and rapid forwarding (< 24 hours). These "shell" accounts exist only to relay funds and add hops.

5. **Velocity Analysis:** Detects accounts where money is received and forwarded within minutes — a strong indicator of automated mule activity.

6. **Layering Detection:** Identifies decreasing-amount chains where each hop deducts a small commission (e.g., $10K → $9.5K → $9K), a common layering technique.

7. **Structuring Detection:** Flags transactions clustered just below reporting thresholds (e.g., multiple $9,900 transactions to avoid the $10,000 reporting requirement).

8. **Community & SCC Clustering:** Uses graph community detection to find tightly connected groups with heavy internal transfers — potential mule rings operating as a unit.

9. **New Account Burst:** Detects freshly created accounts that suddenly show high transaction volume — a red flag for newly recruited mules.

10. **Entropy Analysis:** Calculates Shannon entropy of each account's counterparty distribution. Low entropy (< 1.5) means an account transacts with very few counterparties in a predictable pattern — suspicious for relay behavior.

### Scoring & False-Positive Control

Each account receives a **suspicion score (0–100)** by summing weighted points from all 10 detection patterns. A **Trust Multiplier** discount (up to 40%) is applied to high-degree nodes (≥ 50 connections) with stable timing and no cycle participation — these are likely legitimate merchants, not mules.

### Why Graph Theory?

> Money mule networks are inherently **graph problems**. The criminal patterns (cycles, fan structures, relay chains) are **topological structures** in the transaction network. No amount of single-transaction rule checking can detect a cycle — you must analyze the graph. CrossX brings this graph-aware intelligence to financial crime detection.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the Flask GUI (recommended)
python gui_app.py
```

Open your browser at **http://localhost:5000**.

- Click **⚡ Demo** to run with synthetic data, or upload your own CSV.
- Click **🛡️ Admin** in the header to open the Admin Panel.

---

## 🛡️ Admin Panel

Access at **http://localhost:5000/admin** — provides:

- **Account overview** — all accounts with AI scores, risk levels, detected patterns
- **Flag / Review / Clear** — override AI classification per account
- **Admin notes** — add free-text notes to any account
- **Transaction tracing** — click 🔍 Trace to see:
  - Every sent/received transaction with amounts and timestamps
  - Network graph of connected accounts
  - Stats: total sent, received, net balance, connected accounts
  - Chain-trace into any counterparty's transactions
- **Filters** — filter by flagged / under review / cleared / high-risk
- **Search** — search accounts by ID
- **Bulk actions** — flag all high-risk or review all medium-risk at once
- **CSV export** — download admin review as a CSV file

---

## 📂 Project Structure

```
money-muling-engine/
│
├── app.py                      # Streamlit web UI
├── gui_app.py                  # Flask-based GUI (recommended)
├── run_local.py                # CLI runner
├── detection/
│   ├── cycles.py               # Circular fund routing (DFS cycle detection)
│   ├── smurfing.py             # Fan-in / Fan-out structuring patterns
│   ├── shell_network.py        # Layered pass-through relay detection
│   ├── velocity.py             # Rapid pass-through detection
│   ├── layering.py             # Decreasing-amount chain detection
│   ├── structuring.py          # Threshold avoidance detection
│   ├── community.py            # Community clusters & new account bursts
│   └── scoring.py              # Suspicion scoring engine + entropy
│
├── utils/
│   ├── graph_builder.py        # NetworkX graph construction
│   ├── json_export.py          # JSON report generation
│   ├── sample_data.py          # Synthetic demo data generator
│   └── validation.py           # CSV schema validation & cleaning
│
├── templates/
│   ├── index.html              # Main dashboard UI
│   └── admin.html              # Admin panel UI
│
├── requirements.txt
└── README.md
```

---

## 📄 Input Format

Upload a **CSV** file with these exact columns:

| Column           | Type   | Example                   |
|------------------|--------|---------------------------|
| `transaction_id` | string | `TXN_00001`               |
| `sender_id`      | string | `ACC_00123`               |
| `receiver_id`    | string | `ACC_00456`               |
| `amount`         | float  | `1500.00`                 |
| `timestamp`      | string | `2025-01-15 14:30:00`     |

Timestamp format: **YYYY-MM-DD HH:MM:SS**

---

## 🔍 Detection Patterns

### 1. Circular Fund Routing (Cycles)
Detects directed cycles of length 3–5 using DFS. The classic mule signature:
**A → B → C → A**.

### 2. Smurfing / Structuring
- **Fan-In:** 10+ senders → 1 receiver (collection hub)
- **Fan-Out:** 1 sender → 10+ receivers (distribution hub)
- Time-window clustering and amount variance analysis

### 3. Layered Shell Networks
Traces relay chains where intermediate nodes:
- Have near-zero net balance (money in ≈ money out)
- Low total degree (exist only to relay funds)
- Rapid forwarding window (< 24 hours)

### 4. Suspicion Scoring (0–100 Scale)

This is a **deterministic, rule-based pattern-matching engine** — not a trained ML model. Each account receives a suspicion score by summing weighted points across 10 detection patterns:

| # | Factor                  | Max Weight | How It's Detected |
|---|------------------------|-----------|-------------------|
| 1 | Cycle Participation    | 40 pts    | Circular money flow (A→B→C→A). First cycle = 30 pts, each extra adds 5 |
| 2 | Smurfing Hub           | 30 pts    | Fan-in (many→one) or fan-out (one→many) concentration. +5 for low variance, +5 for timing |
| 3 | Rapid Pass-Through     | 20 pts    | Account in velocity chain — money in→out within minutes |
| 4 | Layering (Decreasing)  | 20 pts    | Decreasing-amount chains (A→B $10k, B→C $9.5k, C→D $9k) |
| 5 | Structuring            | 18 pts    | Transactions just below reporting thresholds (e.g. $9,900) |
| 6 | Shell Pass-Through     | 15 pts    | Near-zero retention — money in ≈ money out, no economic activity |
| 7 | New Account Burst      | 15 pts    | Freshly created account with sudden high transaction volume |
| 8 | Community / SCC        | 12 pts    | Tightly connected group with heavy internal transfers |
| 9 | Amount Consistency     | 10 pts    | Retention < 5% of throughput |
| 10| Low Entropy            | 10 pts    | Predictable counterparty patterns (Shannon entropy < 1.5) |

#### Score Calculation

```
raw_score = sum of all triggered pattern weights
final_score = min(100, raw_score)     # capped at 100
```

#### Risk Classification

| Risk Level | Score Range |
|-----------|-------------|
| 🔴 HIGH   | ≥ 50        |
| 🟡 MEDIUM | 25 – 49     |
| 🟢 LOW    | < 25        |

### 5. False Positive Control
High-degree nodes (≥ 50 connections) with stable timing regularity and no cycle participation receive a **Trust Multiplier** discount (up to 40% reduction).

---

## 📊 Output

### Interactive Graph
- Directed edges (sender → receiver)
- Color-coded by risk level (red/orange/yellow/blue)
- Fraud ring members share a ring colour
- Hover for account details (score, amounts, patterns)

### Downloadable JSON Report

```json
{
  "suspicious_accounts": [
    {
      "account_id": "ACC_00123",
      "suspicion_score": 87.5,
      "detected_patterns": ["cycle_participant_x1", "high_velocity"],
      "ring_id": "RING_001"
    }
  ],
  "fraud_rings": [
    {
      "ring_id": "RING_001",
      "member_accounts": ["ACC_00123", "ACC_00456"],
      "pattern_type": "cycle",
      "risk_score": 95.3
    }
  ],
  "summary": {
    "total_accounts_analyzed": 500,
    "suspicious_accounts_flagged": 15,
    "fraud_rings_detected": 4,
    "processing_time_seconds": 2.3
  }
}
```

### Fraud Ring Summary Table
| Ring ID   | Pattern Type | Member Count | Risk Score | Member Account IDs |
|-----------|-------------|--------------|------------|-------------------|
| RING_001  | cycle       | 3            | 95.3       | ACC_001, ACC_002  |

---

## ⚙️ Performance

- Handles up to **10 000 transactions**
- Typical processing time: **< 30 seconds**
- Efficient use of NetworkX algorithms and pandas vectorized operations

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Flask** — web application framework (GUI)
- **Streamlit** — alternative web UI
- **NetworkX** — graph construction & analysis
- **Pandas / NumPy** — data wrangling
- **vis.js** — interactive graph visualization
- **Tailwind CSS** — UI styling

---

## 📝 License

MIT
