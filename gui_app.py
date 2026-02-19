"""
gui_app.py — Flask-based GUI for the Money Muling Detection Engine.

Run with:  python gui_app.py
Open:      http://localhost:5000
"""

import os
import io
import time
import json
import pandas as pd
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

from utils.validation import validate_csv
from utils.graph_builder import build_transaction_graph, build_simple_digraph
from utils.sample_data import generate_sample_csv
from utils.json_export import generate_report, report_to_json_string
from detection.cycles import detect_cycles
from detection.smurfing import detect_smurfing
from detection.shell_network import detect_shell_networks
from detection.velocity import detect_velocity
from detection.layering import detect_layering
from detection.structuring import detect_structuring
from detection.community import detect_communities, detect_new_accounts
from detection.scoring import compute_suspicion_scores
from detection.account_analysis import analyze_all_accounts, analyze_single_account

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "crossX-money-muling-s3cr3t-key-2026")

# ── Admin credentials ─────────────────────────────────────────────────────────
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "crossX@2026")

# ── Server-side storage for the last analyzed dataset ─────────────────────────
# This allows the admin panel, account explorer, and trace endpoints to access
# the same data that was uploaded/analyzed on the dashboard.
_last_analysis = {
    "df": None,             # cleaned DataFrame from last upload or demo
    "results": None,        # full pipeline results dict
    "G": None,              # MultiDiGraph
    "simple_G": None,       # collapsed DiGraph
    "cycle_results": None,
    "velocity_results": None,
    "layering_results": None,
    "structuring_results": None,
    "account_analyses": None,  # 5-step analysis results for all accounts
}


def admin_required(f):
    """Decorator to protect admin routes with session-based auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            # For API endpoints return 401 JSON; for pages redirect to login
            if request.is_json or request.method == "POST":
                return jsonify({"error": True, "errors": ["Authentication required"], "auth_required": True}), 401
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════
# PATTERN EXPLANATIONS
# ═══════════════════════════════════════════════════════════════

PATTERN_EXPLANATIONS = {
    # ── Cycle patterns ────────────────────────────────────────────────────
    "cycle": {
        "title": "🔄 Circular Money Flow",
        "description": "Money flows in a circular loop between accounts",
        "meaning": "When Account A sends to B, B to C, and C back to A, it creates a suspicious loop. Circular routing is extremely rare in legitimate banking and is a hallmark of money laundering — it disguises the origin of funds by sending them through a chain that loops back.",
        "risk": "HIGH - Indicates deliberate layering to hide money trails",
        "ml_classification": "Circular Fund Routing"
    },
    # ── Smurfing patterns ─────────────────────────────────────────────────
    "fan_in_hub": {
        "title": "🐟 Fan-In Smurfing Hub (Collection Point)",
        "description": "This account receives transactions from many different senders",
        "meaning": "Multiple accounts are funneling money into this single hub — a classic collection-point pattern. Criminals recruit 'smurfs' (mules) who each deposit small amounts to stay below reporting thresholds, then the hub consolidates and forwards the pooled funds.",
        "risk": "HIGH - Collection-point smurfing / threshold evasion",
        "ml_classification": "Smurfing — Collection Hub"
    },
    "fan_out_hub": {
        "title": "🐟 Fan-Out Smurfing Hub (Distribution Point)",
        "description": "This account sends transactions to many different receivers",
        "meaning": "A single account is distributing funds across numerous recipients — a classic fan-out / distribution pattern. After consolidating illicit funds, the controller spreads them out to many accounts, making tracing extremely difficult.",
        "risk": "HIGH - Distribution-point smurfing / threshold evasion",
        "ml_classification": "Smurfing — Distribution Hub"
    },
    "smurfing_peripheral": {
        "title": "🐟 Smurfing Participant",
        "description": "This account is part of a smurfing network but is not the central hub",
        "meaning": "While not the main hub, this account participates in structured fan-in or fan-out transfers. Peripheral mules are often recruited individuals who move money on behalf of the organizer, sometimes unknowingly.",
        "risk": "MEDIUM - Peripheral participant in smurfing network",
        "ml_classification": "Smurfing — Peripheral Mule"
    },
    # ── Shell / Pass-through patterns ─────────────────────────────────────
    "shell_passthrough": {
        "title": "🔗 Shell Pass-Through Account",
        "description": "Account acts as a relay — money enters and exits quickly with near-zero retention",
        "meaning": "This account receives funds and almost immediately forwards them onward, keeping little or nothing. It functions purely as a conduit to add an extra hop in the money trail. Pass-through accounts are a key indicator of layering — each additional hop makes it harder for investigators to trace the true source and destination of funds.",
        "risk": "HIGH - Relay node used to obscure money trail",
        "ml_classification": "Shell / Pass-Through Layering"
    },
    "shell_network_member": {
        "title": "🔗 Shell Network Member",
        "description": "Account belongs to a cluster of accounts behaving like shell entities",
        "meaning": "This account is part of a group that collectively exhibits shell-company-like behavior — high throughput, low retention, and interconnected transfers. Shell networks are used to create complex webs of transactions that frustrate investigators and obscure the beneficial owner of the funds.",
        "risk": "MEDIUM-HIGH - Member of suspected shell network",
        "ml_classification": "Shell Network Participant"
    },
    # ── Velocity / Rapid pass-through ─────────────────────────────────────
    "high_velocity": {
        "title": "⚡ High Transaction Velocity",
        "description": "Unusually high number of transactions per hour",
        "meaning": "This account processes transactions at a rate far above normal. Extremely rapid activity often indicates automated or scripted money movement — funds are pushed through as fast as possible before detection systems or account freezes can intervene.",
        "risk": "MEDIUM-HIGH - Automated rapid money movement",
        "ml_classification": "High-Velocity Transfers"
    },
    "rapid_passthrough": {
        "title": "⚡ Rapid Pass-Through",
        "description": "Similar amounts received and sent within a very short time window",
        "meaning": "Money arrives at this account and a similar (or identical) amount leaves within minutes. This 'in-and-out' pattern with tight timing suggests the account is being used purely as a transit point. When amounts also closely match, it strongly indicates automated layering rather than legitimate commercial activity.",
        "risk": "HIGH - Timed relay with amount matching",
        "ml_classification": "Rapid Pass-Through Layering"
    },
    # ── Layering ──────────────────────────────────────────────────────────
    "layering_chain": {
        "title": "📚 Transaction Layering Chain",
        "description": "Part of a chain where amounts decrease at each step (commission deduction)",
        "meaning": "A → B ($10,000), B → C ($9,500), C → D ($9,000). Each intermediary deducts a small 'commission' before forwarding the rest. This decreasing-amount chain is a textbook layering technique — it distances the money from its criminal source while rewarding each mule in the chain.",
        "risk": "MEDIUM-HIGH - Commission-based relay chain indicates professional money laundering",
        "ml_classification": "Layering — Decreasing-Amount Chain"
    },
    # ── Structuring / Threshold avoidance ─────────────────────────────────
    "structuring": {
        "title": "💰 Structuring / Threshold Avoidance",
        "description": "Multiple transactions deliberately placed just below a reporting threshold",
        "meaning": "This account repeatedly transacts amounts just under a regulatory reporting limit (e.g., many $9,800–$9,999 transactions when the threshold is $10,000). Deliberately splitting transactions to avoid mandatory reporting is itself a federal crime (31 USC §5324) and a strong indicator that the account holder is trying to move large sums undetected.",
        "risk": "HIGH - Deliberate regulatory evasion",
        "ml_classification": "Structuring — Threshold Avoidance"
    },
    "amount_repetition": {
        "title": "💰 Repeated Identical Amounts",
        "description": "Same exact dollar amount appears in many transactions",
        "meaning": "This account sends or receives the same precise amount over and over. Natural economic activity produces varied amounts; highly repetitive identical amounts suggest automated or scripted transfers, often part of a structured money-moving operation.",
        "risk": "MEDIUM - Indicates scripted / automated transfers",
        "ml_classification": "Amount Repetition — Automation Indicator"
    },
    # ── Amount consistency ────────────────────────────────────────────────
    "amount_consistency": {
        "title": "💵 Unusual Amount Consistency",
        "description": "Transactions use suspiciously uniform amounts — money in ≈ money out",
        "meaning": "The total amount received closely matches the total amount sent, with less than 5% retained. In legitimate accounts, inflows and outflows rarely balance this precisely. When they do, it indicates the account is simply passing money through — a hallmark of mule accounts that exist solely to relay funds.",
        "risk": "MEDIUM - May indicate bot-driven transfers",
        "ml_classification": "Amount Consistency — Pass-Through Indicator"
    },
    # ── Low entropy ───────────────────────────────────────────────────────
    "low_entropy": {
        "title": "📊 Low Transaction Entropy",
        "description": "Transaction counterparty pattern is highly predictable / concentrated",
        "meaning": "This account transacts with very few unique counterparties in a highly repetitive way (low Shannon entropy). Normal accounts interact with a variety of parties; a concentrated, predictable pattern suggests an artificial relationship — such as a dedicated mule funneling to or from a single controller.",
        "risk": "MEDIUM - Lacks natural transaction diversity",
        "ml_classification": "Low Entropy — Concentrated Pattern"
    },
    # ── New account burst ─────────────────────────────────────────────────
    "new_account_burst": {
        "title": "✨ New Account Burst",
        "description": "Recently created account with sudden high transaction volume",
        "meaning": "This account was created very recently but immediately began processing a large number or high volume of transactions. Legitimate new accounts typically ramp up gradually. A sudden burst suggests the account was opened specifically for a money-laundering operation and may be abandoned once the funds are moved.",
        "risk": "MEDIUM-HIGH - Fresh account with suspicious burst activity",
        "ml_classification": "New Account — Burst Activity"
    },
    # ── Community / SCC ───────────────────────────────────────────────────
    "tight_community": {
        "title": "🌐 Tight Community Cluster",
        "description": "Member of a tightly interconnected group with heavy internal transfers",
        "meaning": "This account belongs to a small, densely connected group where most transactions stay within the cluster. Such tight communities are uncommon in normal banking and suggest a coordinated ring — accounts controlled by the same entity or criminal group, moving money among themselves to layer and obscure its origin.",
        "risk": "MEDIUM - Possible coordinated money laundering ring",
        "ml_classification": "Community Cluster — Ring Indicator"
    },
    # ── Trust adjustment (informational) ──────────────────────────────────
    "trust_adjusted": {
        "title": "✅ Trust Multiplier Applied",
        "description": "Score reduced — high-degree node with stable timing and no cycle involvement",
        "meaning": "This account has a very high number of counterparties and regular, predictable transaction timing — characteristics of a legitimate merchant or payroll processor. Because it is not involved in any cycles, a trust discount was applied to reduce the false-positive risk.",
        "risk": "LOW - False-positive control adjustment",
        "ml_classification": "Trusted Entity Discount"
    },
}

# Prefix mapping for dynamic pattern names like cycle_participant_x8, rapid_passthrough_x3, etc.
_PATTERN_PREFIX_MAP = {
    "cycle_participant": "cycle",
    "rapid_passthrough": "rapid_passthrough",
    "structuring_below": "structuring",
    "amount_repeat": "amount_repetition",
}


def get_pattern_explanation(pattern_name):
    """Get explanation for a detected pattern.

    Handles exact matches first, then tries prefix matching for dynamic
    pattern names (e.g. cycle_participant_x8 → cycle explanation).
    """
    # 1. Exact match
    if pattern_name in PATTERN_EXPLANATIONS:
        info = dict(PATTERN_EXPLANATIONS[pattern_name])
        info["pattern_id"] = pattern_name
        return info

    # 2. Prefix match for dynamic names
    for prefix, key in _PATTERN_PREFIX_MAP.items():
        if pattern_name.startswith(prefix):
            info = dict(PATTERN_EXPLANATIONS[key])
            info["pattern_id"] = pattern_name
            # Enrich title with specific count if available
            suffix = pattern_name[len(prefix):]
            if suffix.startswith("_x"):
                count = suffix[2:]
                info["title"] = f"{info['title']} (×{count})"
            elif suffix.startswith("_below_"):
                threshold = suffix[7:]
                info["title"] = f"{info['title']} (below ${threshold})"
            return info

    # 3. Fallback
    return {
        "title": pattern_name,
        "pattern_id": pattern_name,
        "description": "Suspicious pattern detected",
        "meaning": "This pattern was flagged as suspicious by the detection engine. It may indicate unusual transaction behavior that warrants further investigation.",
        "risk": "MEDIUM",
        "ml_classification": "General Fraud"
    }


def parse_csv(file_storage=None, use_sample=False):
    """Parse uploaded CSV or generate sample data."""
    if use_sample:
        return generate_sample_csv()

    raw = file_storage.read().decode("utf-8")
    df = pd.read_csv(io.StringIO(raw))

    # Handle CSVs where every row is wrapped in quotes as a single field
    if len(df.columns) == 1 and "," in df.columns[0]:
        cleaned_lines = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith('"') and line.endswith('"'):
                line = line[1:-1]
            cleaned_lines.append(line)
        df = pd.read_csv(io.StringIO("\n".join(cleaned_lines)))

    return df


def run_pipeline(df):
    """Run the full detection pipeline and return structured results."""
    start = time.time()

    is_valid, errors, cleaned_df = validate_csv(df)
    if not is_valid:
        return {"error": True, "errors": errors}

    G = build_transaction_graph(cleaned_df)
    simple_G = build_simple_digraph(G)

    cycle_results = detect_cycles(simple_G)
    smurfing_results = detect_smurfing(G, cleaned_df)
    shell_results = detect_shell_networks(G, simple_G, cleaned_df)
    velocity_results = detect_velocity(G, cleaned_df)
    layering_results = detect_layering(G, cleaned_df)
    structuring_results = detect_structuring(G, cleaned_df)
    community_results = detect_communities(G, simple_G, cleaned_df)
    new_account_results = detect_new_accounts(G, cleaned_df)

    scores = compute_suspicion_scores(
        G, cleaned_df,
        cycle_results, smurfing_results, shell_results,
        velocity_results=velocity_results,
        layering_results=layering_results,
        structuring_results=structuring_results,
        community_results=community_results,
        new_account_results=new_account_results,
    )

    # Run 5-step account analysis
    account_analyses = analyze_all_accounts(
        G, simple_G, cleaned_df,
        cycle_results=cycle_results,
        velocity_results=velocity_results,
        layering_results=layering_results,
        structuring_results=structuring_results,
    )

    # Store graph + detection objects for later per-account queries
    _last_analysis["G"] = G
    _last_analysis["simple_G"] = simple_G
    _last_analysis["cycle_results"] = cycle_results
    _last_analysis["velocity_results"] = velocity_results
    _last_analysis["layering_results"] = layering_results
    _last_analysis["structuring_results"] = structuring_results
    _last_analysis["account_analyses"] = account_analyses

    elapsed = time.time() - start

    # Build structured results for the frontend
    high_risk = [s for s in scores if s["suspicion_score"] >= 50]
    medium_risk = [s for s in scores if 25 <= s["suspicion_score"] < 50]
    low_risk = [s for s in scores if s["suspicion_score"] < 25]

    # Fraud rings
    rings = cycle_results.get("rings", [])
    rings_data = []
    for ring in rings:
        rings_data.append({
            "ring_id": ring.get("ring_id", ""),
            "members": ring.get("member_accounts", []),
            "risk_score": ring.get("risk_score", 0),
            "pattern_type": ring.get("pattern_type", "cycle"),
            "member_count": len(ring.get("member_accounts", [])),
        })

    # Smurfing
    fan_in = smurfing_results.get("fan_in_hubs", [])
    fan_out = smurfing_results.get("fan_out_hubs", [])
    fan_in_data = []
    for hub in fan_in:
        if isinstance(hub, dict):
            fan_in_data.append({
                "account": hub.get("hub_account", "unknown"),
                "counterparties": hub.get("distinct_counterparties", 0),
                "total_amount": round(hub.get("total_amount", 0), 2),
            })
    fan_out_data = []
    for hub in fan_out:
        if isinstance(hub, dict):
            fan_out_data.append({
                "account": hub.get("hub_account", "unknown"),
                "counterparties": hub.get("distinct_counterparties", 0),
                "total_amount": round(hub.get("total_amount", 0), 2),
            })

    # Shell accounts
    shell_accounts = list(shell_results.get("shell_accounts", set()))

    # Velocity
    vel_flagged = list(velocity_results.get("flagged_accounts", set()))
    vel_rapid = velocity_results.get("rapid_accounts", {})
    velocity_data = []
    for acc in vel_flagged:
        events = vel_rapid.get(acc, [])
        velocity_data.append({
            "account": acc,
            "rapid_pairs": len(events),
            "amount_similar": sum(1 for e in events if e.get("amount_similar")),
        })

    # Layering
    lay_chains = layering_results.get("chains", [])
    layering_data = []
    for c in lay_chains:
        layering_data.append({
            "accounts": c.get("accounts", []),
            "amounts": c.get("amounts", []),
            "avg_deduction_pct": c.get("avg_deduction_pct", 0),
        })

    # Structuring
    struct_accts = structuring_results.get("structuring_accounts", {})
    structuring_data = []
    for acc, detail in struct_accts.items():
        structuring_data.append({
            "account": acc,
            "threshold": detail.get("threshold", 0),
            "count": detail.get("count_below", 0),
            "mean_amount": detail.get("mean_amount", 0),
        })

    rep_accts = structuring_results.get("amount_repeat_accounts", {})
    repeat_data = []
    for acc, detail in rep_accts.items():
        repeat_data.append({
            "account": acc,
            "repeated_amount": detail.get("repeated_amount", 0),
            "count": detail.get("count", 0),
        })

    # Communities
    comms = community_results.get("communities", [])
    community_data = []
    for c in comms:
        community_data.append({
            "members": c.get("members", []),
            "density": round(c.get("density", 0), 4),
            "internal_flow": round(c.get("internal_flow", 0), 2),
        })

    sccs = community_results.get("scc_components", [])
    scc_data = []
    for c in sccs:
        scc_data.append({"members": c.get("members", [])})

    # New account bursts
    new_accts = new_account_results.get("new_accounts", [])
    new_account_data = []
    for acc in new_accts:
        new_account_data.append({
            "account": acc.get("account_id", ""),
            "active_days": acc.get("active_days", 0),
            "tx_count": acc.get("tx_count", 0),
            "total_volume": round(acc.get("total_volume", 0), 2),
        })

    # ── Build graph visualization data ────────────────────────────────────
    # Collect per-account info for the graph
    score_map = {s["account_id"]: s for s in scores}
    cycle_accounts = cycle_results.get("cycle_accounts", set())

    # Map accounts to ring IDs for coloring
    account_ring_map = {}
    for ring in rings:
        rid = ring.get("ring_id", "")
        for member in ring.get("member_accounts", []):
            account_ring_map[member] = rid

    # Build vis.js nodes
    graph_nodes = []
    for node in G.nodes():
        ndata = G.nodes[node]
        sinfo = score_map.get(node, {})
        sc = sinfo.get("suspicion_score", 0)
        patterns = sinfo.get("detected_patterns", [])
        ring_id = account_ring_map.get(node, None)
        is_cycle = node in cycle_accounts
        is_shell = node in shell_results.get("shell_accounts", set())

        # Determine risk level
        if sc >= 50:
            risk = "high"
        elif sc >= 25:
            risk = "medium"
        else:
            risk = "low"

        graph_nodes.append({
            "id": node,
            "score": sc,
            "risk": risk,
            "patterns": patterns,
            "ring_id": ring_id,
            "is_cycle": is_cycle,
            "is_shell": is_shell,
            "total_sent": round(ndata.get("total_sent", 0), 2),
            "total_received": round(ndata.get("total_received", 0), 2),
            "net_flow": round(ndata.get("net_flow", 0), 2),
            "tx_count": ndata.get("tx_count", 0),
        })

    # Build vis.js edges (collapse multi-edges)
    edge_agg = {}
    for u, v, data in G.edges(data=True):
        key = (u, v)
        if key not in edge_agg:
            edge_agg[key] = {"amount": 0, "count": 0}
        edge_agg[key]["amount"] += data["amount"]
        edge_agg[key]["count"] += 1

    graph_edges = []
    for (u, v), info in edge_agg.items():
        graph_edges.append({
            "from": u,
            "to": v,
            "amount": round(info["amount"], 2),
            "count": info["count"],
        })

    # All scores for the table - with explanations
    all_scores = []
    for s in scores:
        # Build pattern explanations
        patterns = s.get("detected_patterns", [])
        pattern_details = []
        for p in patterns:
            exp = get_pattern_explanation(p)
            pattern_details.append({
                "name": p,
                "title": exp.get("title", p),
                "description": exp.get("description", ""),
                "meaning": exp.get("meaning", ""),
                "risk": exp.get("risk", "MEDIUM"),
                "ml_classification": exp.get("ml_classification", "General Fraud"),
                "pattern_id": exp.get("pattern_id", p),
            })
        
        all_scores.append({
            "account_id": s["account_id"],
            "score": s["suspicion_score"],
            "patterns": patterns,
            "pattern_details": pattern_details,
            "ring_id": s.get("ring_id"),
            "risk_level": "high" if s["suspicion_score"] >= 50 else "medium" if s["suspicion_score"] >= 25 else "low",
            "why_suspicious": f"This account scored {s['suspicion_score']:.1f}/100 due to {len(patterns)} detected pattern(s): {', '.join(patterns) if patterns else 'baseline activity'}",
            "score_breakdown": s.get("score_breakdown", {}),
        })

    # Generate JSON report
    report = generate_report(
        scores=scores,
        cycle_results=cycle_results,
        smurfing_results=smurfing_results,
        shell_results=shell_results,
        total_accounts=G.number_of_nodes(),
        processing_time=elapsed,
    )

    return {
        "error": False,
        "summary": {
            "total_accounts": G.number_of_nodes(),
            "total_transactions": G.number_of_edges(),
            "high_risk": len(high_risk),
            "medium_risk": len(medium_risk),
            "low_risk": len(low_risk),
            "total_cycles": len(cycle_results.get("cycles", [])),
            "cycle_accounts": len(cycle_results.get("cycle_accounts", set())),
            "fan_in_hubs": len(fan_in),
            "fan_out_hubs": len(fan_out),
            "shell_accounts": len(shell_accounts),
            "velocity_flagged": len(vel_flagged),
            "layering_chains": len(lay_chains),
            "structuring_flagged": len(structuring_data),
            "communities": len(community_data),
            "new_account_bursts": len(new_account_data),
            "processing_time": round(elapsed, 2),
        },
        "scores": all_scores,
        "rings": rings_data,
        "smurfing": {"fan_in": fan_in_data, "fan_out": fan_out_data},
        "shell_accounts": shell_accounts[:50],
        "velocity": velocity_data,
        "layering": layering_data,
        "structuring": structuring_data,
        "amount_repetition": repeat_data,
        "communities": community_data,
        "scc_components": scc_data,
        "new_accounts": new_account_data,
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "report_json": report_to_json_string(report),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        use_sample = request.form.get("use_sample") == "true"
        if use_sample:
            df = parse_csv(use_sample=True)
        else:
            if "file" not in request.files or request.files["file"].filename == "":
                return jsonify({"error": True, "errors": ["No file uploaded."]})
            df = parse_csv(file_storage=request.files["file"])

        results = run_pipeline(df)

        # Store the analyzed data so admin panel / explorer / trace can use it
        if not results.get("error"):
            is_valid, _errs, cleaned_df = validate_csv(df)
            _last_analysis["df"] = cleaned_df if is_valid else df
            _last_analysis["results"] = results

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


# ── Account Explorer helpers ─────────────────────────────────────────────────

def get_account_transactions(df: pd.DataFrame, account_id: str) -> pd.DataFrame:
    """Filter all transactions where sender_id or receiver_id equals account_id."""
    mask = (df["sender_id"] == account_id) | (df["receiver_id"] == account_id)
    return df[mask].copy()


def build_account_graph(df: pd.DataFrame, account_id: str):
    """Build a directed ego-graph around *account_id*.

    Returns
    -------
    dict with keys: nodes, edges, stats
    """
    txns = get_account_transactions(df, account_id)
    if txns.empty:
        return None

    import networkx as nx

    G = nx.MultiDiGraph()
    for _, row in txns.iterrows():
        G.add_edge(
            row["sender_id"],
            row["receiver_id"],
            amount=float(row["amount"]),
            transaction_id=row["transaction_id"],
            timestamp=str(row["timestamp"]),
        )

    # ── Stats ─────────────────────────────────────────────────────────────
    sent_df = txns[txns["sender_id"] == account_id]
    recv_df = txns[txns["receiver_id"] == account_id]

    total_sent = float(sent_df["amount"].sum())
    total_received = float(recv_df["amount"].sum())
    net_balance = total_received - total_sent

    connected = set(txns["sender_id"]) | set(txns["receiver_id"])
    connected.discard(account_id)

    in_degree = len(recv_df["sender_id"].unique())
    out_degree = len(sent_df["receiver_id"].unique())

    stats = {
        "account_id": account_id,
        "total_sent": round(total_sent, 2),
        "total_received": round(total_received, 2),
        "net_balance": round(net_balance, 2),
        "num_transactions": len(txns),
        "connected_accounts": len(connected),
        "in_degree": in_degree,
        "out_degree": out_degree,
    }

    # ── Graph nodes ───────────────────────────────────────────────────────
    nodes = []
    for node in G.nodes():
        nodes.append({
            "id": node,
            "is_center": node == account_id,
        })

    # ── Graph edges (individual transactions, not aggregated) ─────────────
    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({
            "from": u,
            "to": v,
            "amount": round(data["amount"], 2),
            "transaction_id": data["transaction_id"],
            "timestamp": data["timestamp"],
        })

    # ── Transaction table rows ────────────────────────────────────────────
    table = []
    for _, row in txns.sort_values("timestamp", ascending=False).iterrows():
        direction = "SENT" if row["sender_id"] == account_id else "RECEIVED"
        counterparty = row["receiver_id"] if direction == "SENT" else row["sender_id"]
        table.append({
            "transaction_id": row["transaction_id"],
            "direction": direction,
            "counterparty": counterparty,
            "amount": round(float(row["amount"]), 2),
            "timestamp": str(row["timestamp"]),
        })

    return {"nodes": nodes, "edges": edges, "stats": stats, "transactions": table}


@app.route("/account-explorer", methods=["POST"])
def account_explorer():
    """Return ego-graph + stats for a single account."""
    try:
        account_id = request.json.get("account_id", "").strip()

        if not account_id:
            return jsonify({"error": True, "errors": ["No account_id provided."]})

        # Use stored data from last analysis; fall back to sample
        if _last_analysis["df"] is not None:
            cleaned_df = _last_analysis["df"]
        else:
            df = generate_sample_csv()
            is_valid, errors, cleaned_df = validate_csv(df)
            if not is_valid:
                return jsonify({"error": True, "errors": errors})

        result = build_account_graph(cleaned_df, account_id)
        if result is None:
            return jsonify({"error": True, "errors": [f"Account '{account_id}' not found in the dataset."]})

        # Also include the account list for the dropdown
        all_accounts = sorted(set(cleaned_df["sender_id"]) | set(cleaned_df["receiver_id"]))

        return jsonify({"error": False, **result, "all_accounts": all_accounts})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


@app.route("/account-list", methods=["POST"])
def account_list():
    """Return all account IDs in the current dataset."""
    try:
        # Use stored data from last analysis; fall back to sample
        if _last_analysis["df"] is not None:
            cleaned_df = _last_analysis["df"]
        else:
            df = generate_sample_csv()
            _, _, cleaned_df = validate_csv(df)
        all_accounts = sorted(set(cleaned_df["sender_id"]) | set(cleaned_df["receiver_id"]))
        return jsonify({"error": False, "accounts": all_accounts})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


# ══════════════════════════════════════════════════════════════════
# ADMIN AUTH
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET"])
def admin_login_page():
    """Serve the admin login page."""
    if session.get("admin_authenticated"):
        return redirect(url_for("admin_page"))
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    """Authenticate admin credentials."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_authenticated"] = True
        return jsonify({"error": False, "message": "Login successful"})
    return jsonify({"error": True, "errors": ["Invalid username or password"]}), 401


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Clear admin session."""
    session.pop("admin_authenticated", None)
    return jsonify({"error": False, "message": "Logged out"})


# ══════════════════════════════════════════════════════════════════
# ADMIN PANEL (protected)
# ══════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_page():
    """Serve the admin panel."""
    return render_template("admin.html")


@app.route("/admin/data", methods=["POST"])
@admin_required
def admin_data():
    """Return all accounts with scores, patterns for the admin table."""
    try:
        # Use stored results from last analysis; fall back to sample
        if _last_analysis["results"] is not None:
            results = _last_analysis["results"]
        else:
            df = generate_sample_csv()
            results = run_pipeline(df)
            if not results.get("error"):
                is_valid, _errs, cleaned_df = validate_csv(df)
                _last_analysis["df"] = cleaned_df if is_valid else df
                _last_analysis["results"] = results

        if results.get("error"):
            return jsonify(results)

        accounts = []
        for s in results["scores"]:
            accounts.append({
                "account_id": s["account_id"],
                "score": s["score"],
                "patterns": s.get("patterns", []),
                "why_suspicious": s.get("why_suspicious", ""),
                "pattern_details": s.get("pattern_details", []),
            })

        return jsonify({"error": False, "accounts": accounts})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


@app.route("/admin/report", methods=["POST"])
@admin_required
def admin_report():
    """Generate downloadable JSON report in the required output format."""
    try:
        overrides = request.json.get("overrides", {}) if request.json else {}

        # Use stored results from last analysis; fall back to sample
        if _last_analysis["results"] is not None:
            results = _last_analysis["results"]
        else:
            df = generate_sample_csv()
            results = run_pipeline(df)
            if not results.get("error"):
                is_valid, _errs, cleaned_df = validate_csv(df)
                _last_analysis["df"] = cleaned_df if is_valid else df
                _last_analysis["results"] = results

        if results.get("error"):
            return jsonify(results)

        # Build suspicious_accounts list
        suspicious_accounts = []
        for s in results["scores"]:
            # Determine effective status
            acct_id = s["account_id"]
            if acct_id in overrides:
                admin_status = overrides[acct_id].get("status", "")
            else:
                admin_status = "flagged" if s["score"] >= 50 else (
                    "review" if s["score"] >= 25 else "cleared"
                )

            # Only include flagged/review accounts
            if admin_status == "cleared":
                continue

            ring_ids = []
            for ring in results.get("rings", []):
                if acct_id in ring.get("members", []):
                    ring_ids.append(ring.get("ring_id", ""))

            suspicious_accounts.append({
                "account_id": acct_id,
                "suspicion_score": s["score"],
                "detected_patterns": s.get("patterns", []),
                "ring_id": ring_ids[0] if ring_ids else None,
            })

        # Build fraud_rings list
        fraud_rings = []
        for ring in results.get("rings", []):
            fraud_rings.append({
                "ring_id": ring.get("ring_id", ""),
                "member_accounts": ring.get("members", []),
                "pattern_type": ring.get("pattern_type", "cycle"),
                "risk_score": ring.get("risk_score", 0),
            })

        # Build summary
        summary = results.get("summary", {})
        report = {
            "suspicious_accounts": suspicious_accounts,
            "fraud_rings": fraud_rings,
            "summary": {
                "total_accounts_analyzed": summary.get("total_accounts", 0),
                "suspicious_accounts_flagged": len(suspicious_accounts),
                "fraud_rings_detected": len(fraud_rings),
                "processing_time_seconds": summary.get("processing_time", 0),
            },
        }

        return jsonify({"error": False, "report": report})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


@app.route("/admin/trace", methods=["POST"])
@admin_required
def admin_trace():
    """Return full transaction trace for a single account."""
    try:
        account_id = request.json.get("account_id", "").strip()
        if not account_id:
            return jsonify({"error": True, "errors": ["No account_id provided."]})

        # Use stored data from last analysis; fall back to sample
        if _last_analysis["df"] is not None:
            cleaned_df = _last_analysis["df"]
        else:
            df = generate_sample_csv()
            is_valid, errors, cleaned_df = validate_csv(df)
            if not is_valid:
                return jsonify({"error": True, "errors": errors})

        result = build_account_graph(cleaned_df, account_id)
        if result is None:
            return jsonify({"error": True, "errors": [f"Account '{account_id}' not found."]})

        return jsonify({"error": False, **result})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


# ══════════════════════════════════════════════════════════════════
# ACCOUNT ANALYSIS — 5-STEP BEHAVIORAL CLASSIFICATION
# ══════════════════════════════════════════════════════════════════

@app.route("/admin/account-analysis", methods=["POST"])
@admin_required
def admin_account_analysis():
    """Return 5-step behavioral analysis for all accounts or a single account.

    POST body (JSON):
        account_id (optional): If provided, analyze just that account.
                                If omitted, return all account analyses.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_account = data.get("account_id", "").strip()

        # If we already have cached analyses, use them
        if _last_analysis["account_analyses"] is not None:
            analyses = _last_analysis["account_analyses"]

            if target_account:
                # Find the specific account
                match = next(
                    (a for a in analyses if a["account_id"] == target_account),
                    None,
                )
                if match is None:
                    # Try running a fresh single-account analysis
                    if _last_analysis["G"] is not None and _last_analysis["df"] is not None:
                        match = analyze_single_account(
                            target_account,
                            _last_analysis["G"],
                            _last_analysis["simple_G"],
                            _last_analysis["df"],
                            _last_analysis["cycle_results"] or {},
                            _last_analysis["velocity_results"] or {},
                            _last_analysis["layering_results"] or {},
                            _last_analysis["structuring_results"] or {},
                        )
                    else:
                        return jsonify({"error": True, "errors": [f"Account '{target_account}' not found."]})

                return jsonify({"error": False, "analysis": match})
            else:
                return jsonify({"error": False, "analyses": analyses})

        # No cached data — run the pipeline first
        if _last_analysis["df"] is not None:
            cleaned_df = _last_analysis["df"]
        else:
            cleaned_df = generate_sample_csv()
            is_valid, errors, cleaned_df = validate_csv(cleaned_df)
            if not is_valid:
                return jsonify({"error": True, "errors": errors})

        # Build graph and run detection
        G = build_transaction_graph(cleaned_df)
        simple_G = build_simple_digraph(G)
        cycle_results = detect_cycles(simple_G)
        velocity_results = detect_velocity(G, cleaned_df)
        layering_results = detect_layering(G, cleaned_df)
        structuring_results = detect_structuring(G, cleaned_df)

        analyses = analyze_all_accounts(
            G, simple_G, cleaned_df,
            cycle_results=cycle_results,
            velocity_results=velocity_results,
            layering_results=layering_results,
            structuring_results=structuring_results,
        )

        # Cache
        _last_analysis["G"] = G
        _last_analysis["simple_G"] = simple_G
        _last_analysis["cycle_results"] = cycle_results
        _last_analysis["velocity_results"] = velocity_results
        _last_analysis["layering_results"] = layering_results
        _last_analysis["structuring_results"] = structuring_results
        _last_analysis["account_analyses"] = analyses

        if target_account:
            match = next(
                (a for a in analyses if a["account_id"] == target_account),
                None,
            )
            if match is None:
                return jsonify({"error": True, "errors": [f"Account '{target_account}' not found."]})
            return jsonify({"error": False, "analysis": match})

        return jsonify({"error": False, "analyses": analyses})

    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


@app.route("/account-analysis/<account_id>", methods=["GET"])
def public_account_analysis(account_id: str):
    """Public endpoint: get 5-step analysis for a specific account (no auth)."""
    try:
        account_id = account_id.strip()
        if not account_id:
            return jsonify({"error": True, "errors": ["No account_id provided."]})

        if _last_analysis["account_analyses"] is not None:
            match = next(
                (a for a in _last_analysis["account_analyses"]
                 if a["account_id"] == account_id),
                None,
            )
            if match:
                return jsonify({"error": False, "analysis": match})

        # Try fresh analysis
        if _last_analysis["G"] is not None and _last_analysis["df"] is not None:
            analysis = analyze_single_account(
                account_id,
                _last_analysis["G"],
                _last_analysis["simple_G"],
                _last_analysis["df"],
                _last_analysis["cycle_results"] or {},
                _last_analysis["velocity_results"] or {},
                _last_analysis["layering_results"] or {},
                _last_analysis["structuring_results"] or {},
            )
            return jsonify({"error": False, "analysis": analysis})

        return jsonify({"error": True, "errors": ["No data analyzed yet. Upload a CSV or run Demo first."]})

    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    print("\n  Money Muling Detection Engine — GUI")
    print("  Open http://localhost:5000 in your browser\n")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(debug=debug, host="0.0.0.0", port=port)
