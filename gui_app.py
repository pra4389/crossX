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
from flask import Flask, render_template, request, jsonify

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

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload


# ═══════════════════════════════════════════════════════════════
# PATTERN EXPLANATIONS
# ═══════════════════════════════════════════════════════════════

PATTERN_EXPLANATIONS = {
    "cycle": {
        "title": "🔄 Circular Money Flow",
        "description": "Money flows in a circular loop between accounts",
        "meaning": "When Account A sends to B, B to C, and C back to A, it creates a suspicious loop. Often used to obfuscate the original source of money.",
        "risk": "HIGH - Indicates deliberate layering to hide money trails"
    },
    "smurfing": {
        "title": "🐟 Smurfing Activity",
        "description": "Many small transactions from/to a single hub account",
        "meaning": "Multiple accounts sending small amounts to one account (like collecting tips at a bar), or one account distributing to many. Used to bypass transaction thresholds.",
        "risk": "HIGH - Typical structuring/threshold evasion technique"
    },
    "shell": {
        "title": "🔗 Shell/Pass-Through Account",
        "description": "Account quickly moves money without adding value",
        "meaning": "Money enters and quickly exits with minimal delay (e.g., $10,000 in, $9,900 out in 5 minutes). Acts as a middleman.",
        "risk": "MEDIUM-HIGH - Used to hide the true recipient"
    },
    "velocity": {
        "title": "⚡ Rapid Pass-Through",
        "description": "Money flowing through account very quickly",
        "meaning": "High-speed transaction chains where similar amounts move through multiple accounts in short time windows. Suggests automatic layering.",
        "risk": "MEDIUM-HIGH - Pattern of rapid money movement"
    },
    "layering": {
        "title": "📚 Transaction Layering",
        "description": "Chain of transactions with decreasing amounts",
        "meaning": "A → B ($10k), B → C ($9.5k), C → D ($9k). Each step deducts a small commission. Makes it hard to trace the original source.",
        "risk": "MEDIUM - Commission-like pattern suggests professional money laundering"
    },
    "structuring": {
        "title": "💰 Structuring/Threshold Avoidance",
        "description": "Multiple transactions just below reporting threshold",
        "meaning": "Intentional breaking of large amounts into smaller chunks (e.g., ten $9,900 transfers instead of one $99k). Illegal to deliberately avoid reporting thresholds.",
        "risk": "HIGH - Deliberate regulatory evasion"
    },
    "community": {
        "title": "🌐 Suspicious Community Cluster",
        "description": "Tightly connected group with heavy internal transfers",
        "meaning": "A group of accounts that heavily transfer money among themselves. Suggests controlled network rather than organic transactions.",
        "risk": "MEDIUM - Possible money laundering ring"
    },
    "new_account": {
        "title": "✨ New Account Burst",
        "description": "Newly created account with sudden high transaction volume",
        "meaning": "Account created recently but immediately shows unusual activity patterns. Often used for one-time money laundering operations.",
        "risk": "MEDIUM-HIGH - Fresh accounts with suspicious behavior"
    },
    "amount_consistency": {
        "title": "💵 Unusual Amount Consistency",
        "description": "Transactions use suspiciously uniform amounts",
        "meaning": "Many identical amounts (e.g., always exactly $5,000). Natural transactions vary; artificial consistency suggests automation.",
        "risk": "MEDIUM - May indicate bot-driven transfers"
    },
    "entropy": {
        "title": "📊 Low Information Entropy",
        "description": "Low diversity in transaction patterns",
        "meaning": "Transactions are too uniform/predictable. Real economic activity varies; this suggests artificially controlled flows.",
        "risk": "MEDIUM - Pattern lacks natural randomness"
    }
}


def get_pattern_explanation(pattern_name):
    """Get explanation for a detected pattern."""
    if pattern_name in PATTERN_EXPLANATIONS:
        return PATTERN_EXPLANATIONS[pattern_name]
    return {
        "title": pattern_name,
        "description": "Unknown pattern detected",
        "meaning": "This pattern indicates suspicious activity",
        "risk": "MEDIUM"
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
                "risk": exp.get("risk", "MEDIUM")
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
        use_sample = request.json.get("use_sample", True)

        if not account_id:
            return jsonify({"error": True, "errors": ["No account_id provided."]})

        if use_sample:
            df = generate_sample_csv()
        else:
            return jsonify({"error": True, "errors": ["Upload not supported yet — use sample data."]})

        # Validate
        from utils.validation import validate_csv
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
    """Return all account IDs in the sample dataset for the dropdown."""
    try:
        df = generate_sample_csv()
        from utils.validation import validate_csv
        _, _, cleaned_df = validate_csv(df)
        all_accounts = sorted(set(cleaned_df["sender_id"]) | set(cleaned_df["receiver_id"]))
        return jsonify({"error": False, "accounts": all_accounts})
    except Exception as e:
        return jsonify({"error": True, "errors": [str(e)]})


# ══════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ══════════════════════════════════════════════════════════════════

@app.route("/admin")
def admin_page():
    """Serve the admin panel."""
    return render_template("admin.html")


@app.route("/admin/data", methods=["POST"])
def admin_data():
    """Return all accounts with scores, patterns for the admin table."""
    try:
        df = generate_sample_csv()
        results = run_pipeline(df)
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


@app.route("/admin/trace", methods=["POST"])
def admin_trace():
    """Return full transaction trace for a single account."""
    try:
        account_id = request.json.get("account_id", "").strip()
        if not account_id:
            return jsonify({"error": True, "errors": ["No account_id provided."]})

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


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    print("\n  Money Muling Detection Engine — GUI")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
