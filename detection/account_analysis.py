"""
account_analysis.py — Comprehensive 5-Step Per-Account Behavioral Analysis.

For each account, this module performs:

  STEP 1 — Graph Backtracking    (cycle/loop/rapid-forward detection)
  STEP 2 — Timing Behavior       (CV analysis, burst, off-hours, automation)
  STEP 3 — Distinct Amount Analysis (repetition, threshold, layering, rounding)
  STEP 4 — Behavior Classification (MERCHANT / FRIEND / SUSPICIOUS)
  STEP 5 — Structured Output     (per-account JSON with score breakdown)

This produces a richer, more explainable classification than the raw suspicion
score alone.
"""

from __future__ import annotations

import math
import numpy as np
import pandas as pd
import networkx as nx
from typing import Dict, List, Set, Any, Optional
from collections import Counter, defaultdict
from datetime import time as dtime


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Step 1 — Graph Backtracking
BACKTRACK_MIN_DEPTH: int = 3
BACKTRACK_MAX_DEPTH: int = 5
RAPID_FORWARD_MINUTES: float = 30.0

# Step 2 — Timing
CV_STABLE: float = 0.3          # CV < 0.3 → stable (merchant-like)
CV_MODERATE_UPPER: float = 0.8  # 0.3 ≤ CV ≤ 0.8 → moderate
BURST_WINDOW_MINUTES: float = 10.0
BURST_MIN_TXN: int = 3
BUSINESS_HOUR_START: int = 8    # 08:00
BUSINESS_HOUR_END: int = 18     # 18:00
AUTOMATION_TOLERANCE_SECONDS: float = 120.0  # 2-minute window for same-minute detection

# Step 3 — Amount Analysis
AML_THRESHOLDS: List[float] = [10000.0, 5000.0, 3000.0, 15000.0]
BELOW_THRESHOLD_PCT: float = 0.10
REPEAT_MIN: int = 3
REPEAT_TOLERANCE: float = 0.02
ROUND_TOLERANCE: float = 50.0   # amounts within $50 of a round number
LAYERING_MIN_CHAIN: int = 3
LAYERING_DECREASE_PCT: float = 0.15  # max 15% decrease per hop

# Step 4 — Classification thresholds
MERCHANT_MIN_IN_DEGREE: int = 50
FRIEND_MAX_DEGREE: int = 15          # P2P accounts typically have few connections

# Score weights
WEIGHT_GRAPH: float = 40.0
WEIGHT_TIMING: float = 30.0
WEIGHT_AMOUNT: float = 30.0


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_all_accounts(
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    cycle_results: Dict[str, Any],
    velocity_results: Dict[str, Any],
    layering_results: Dict[str, Any],
    structuring_results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Run the full 5-step analysis on every account in the graph.

    Returns a list of per-account analysis dicts sorted by risk_score descending.
    """
    all_accounts = sorted(G.nodes())
    results = []

    # Pre-compute shared data
    cycle_accounts = cycle_results.get("cycle_accounts", set())
    account_cycle_count = cycle_results.get("account_cycle_count", {})
    velocity_flagged = velocity_results.get("flagged_accounts", set()) if velocity_results else set()
    rapid_accounts = velocity_results.get("rapid_accounts", {}) if velocity_results else {}
    layering_accounts = layering_results.get("layering_accounts", set()) if layering_results else set()
    structuring_flagged = structuring_results.get("flagged_accounts", set()) if structuring_results else set()
    structuring_details = structuring_results.get("structuring_accounts", {}) if structuring_results else {}
    repeat_flagged = structuring_results.get("repeat_flagged", set()) if structuring_results else set()

    for account_id in all_accounts:
        analysis = _analyze_single_account(
            account_id=account_id,
            G=G,
            simple_G=simple_G,
            df=df,
            cycle_accounts=cycle_accounts,
            account_cycle_count=account_cycle_count,
            velocity_flagged=velocity_flagged,
            rapid_accounts=rapid_accounts,
            layering_accounts=layering_accounts,
            structuring_flagged=structuring_flagged,
            structuring_details=structuring_details,
            repeat_flagged=repeat_flagged,
        )
        results.append(analysis)

    # Sort by risk_score descending
    results.sort(key=lambda x: -x["risk_score"])
    return results


def analyze_single_account(
    account_id: str,
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    cycle_results: Dict[str, Any],
    velocity_results: Dict[str, Any],
    layering_results: Dict[str, Any],
    structuring_results: Dict[str, Any],
) -> Dict[str, Any]:
    """Run the full 5-step analysis on a single account.

    Convenience wrapper that unpacks the results dicts.
    """
    cycle_accounts = cycle_results.get("cycle_accounts", set())
    account_cycle_count = cycle_results.get("account_cycle_count", {})
    velocity_flagged = velocity_results.get("flagged_accounts", set()) if velocity_results else set()
    rapid_accounts = velocity_results.get("rapid_accounts", {}) if velocity_results else {}
    layering_accounts = layering_results.get("layering_accounts", set()) if layering_results else set()
    structuring_flagged = structuring_results.get("flagged_accounts", set()) if structuring_results else set()
    structuring_details = structuring_results.get("structuring_accounts", {}) if structuring_results else {}
    repeat_flagged = structuring_results.get("repeat_flagged", set()) if structuring_results else set()

    return _analyze_single_account(
        account_id=account_id,
        G=G,
        simple_G=simple_G,
        df=df,
        cycle_accounts=cycle_accounts,
        account_cycle_count=account_cycle_count,
        velocity_flagged=velocity_flagged,
        rapid_accounts=rapid_accounts,
        layering_accounts=layering_accounts,
        structuring_flagged=structuring_flagged,
        structuring_details=structuring_details,
        repeat_flagged=repeat_flagged,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL — CORE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _analyze_single_account(
    account_id: str,
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    cycle_accounts: Set[str],
    account_cycle_count: Dict[str, int],
    velocity_flagged: Set[str],
    rapid_accounts: Dict[str, list],
    layering_accounts: Set[str],
    structuring_flagged: Set[str],
    structuring_details: Dict[str, dict],
    repeat_flagged: Set[str],
) -> Dict[str, Any]:
    """Perform all 5 steps on a single account."""

    # ── STEP 1: Graph Backtracking ────────────────────────────────────────
    graph_result = _step1_graph_backtracking(
        account_id, G, simple_G, df,
        cycle_accounts, account_cycle_count,
        velocity_flagged, rapid_accounts,
    )

    # ── STEP 2: Timing Behavior Analysis ──────────────────────────────────
    timing_result = _step2_timing_behavior(account_id, df)

    # ── STEP 3: Distinct Amount Analysis ──────────────────────────────────
    amount_result = _step3_amount_analysis(
        account_id, df,
        layering_accounts, structuring_flagged,
        structuring_details, repeat_flagged,
    )

    # ── STEP 4: Behavior Classification ───────────────────────────────────
    classification = _step4_classify(
        account_id, G, simple_G, df,
        graph_result, timing_result, amount_result,
    )

    # ── STEP 5: Output Format ─────────────────────────────────────────────
    return _step5_build_output(
        account_id, graph_result, timing_result,
        amount_result, classification,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — GRAPH BACKTRACKING
# ═══════════════════════════════════════════════════════════════════════════════

def _step1_graph_backtracking(
    account_id: str,
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    cycle_accounts: Set[str],
    account_cycle_count: Dict[str, int],
    velocity_flagged: Set[str],
    rapid_accounts: Dict[str, list],
) -> Dict[str, Any]:
    """Depth-based backtracking from the account node.

    Checks:
    - Does money return to origin? (cycle detection)
    - Are there short loops? (A → B → C → A)
    - Is there rapid forwarding behavior?
    - Does money pass through multiple nodes quickly?

    Returns a dict with findings and a graph_score (0–100).
    """
    result: Dict[str, Any] = {
        "cycle_detected": False,
        "cycle_count": 0,
        "short_loops": [],
        "rapid_forwarding": False,
        "rapid_event_count": 0,
        "multi_hop_rapid": False,
        "return_flow_detected": False,
        "flow_type": "unknown",  # "linear" or "circular" or "mixed"
        "graph_score": 0.0,
        "findings": [],
    }

    score = 0.0

    # ── Cycle detection ───────────────────────────────────────────────────
    n_cycles = account_cycle_count.get(account_id, 0)
    if n_cycles > 0 or account_id in cycle_accounts:
        result["cycle_detected"] = True
        result["cycle_count"] = max(n_cycles, 1)
        result["return_flow_detected"] = True
        # First cycle = 30 pts, extras diminishing
        score += min(40.0, 30.0 + 5.0 * min(n_cycles - 1, 2))
        result["findings"].append(
            f"Participates in {n_cycles} cycle(s) — money returns to origin"
        )

    # ── Short loop detection via DFS from this node ───────────────────────
    if account_id in simple_G:
        short_loops = _find_short_loops(simple_G, account_id, max_depth=BACKTRACK_MAX_DEPTH)
        result["short_loops"] = short_loops
        if short_loops and not result["cycle_detected"]:
            # Loops found that weren't in the global cycle results (partial loops)
            score += min(15.0, 5.0 * len(short_loops))
            result["findings"].append(
                f"Found {len(short_loops)} short loop(s) involving this account"
            )

    # ── Rapid forwarding ──────────────────────────────────────────────────
    if account_id in velocity_flagged:
        events = rapid_accounts.get(account_id, [])
        result["rapid_forwarding"] = True
        result["rapid_event_count"] = len(events)
        # Check for multi-hop rapid chains
        multi_hop = any(
            ev.get("amount_similar", False) for ev in events
        )
        result["multi_hop_rapid"] = multi_hop
        score += min(20.0, 10.0 + 3.0 * min(len(events), 5))
        if multi_hop:
            score += 5.0
        result["findings"].append(
            f"Rapid pass-through detected: {len(events)} event(s), "
            f"multi-hop={'yes' if multi_hop else 'no'}"
        )

    # ── Determine flow type ───────────────────────────────────────────────
    if result["cycle_detected"]:
        result["flow_type"] = "circular"
    elif result["rapid_forwarding"]:
        result["flow_type"] = "mixed"
    else:
        # Check if flow is linear (Customer → Merchant → Bank pattern)
        if account_id in simple_G:
            in_deg = simple_G.in_degree(account_id)
            out_deg = simple_G.out_degree(account_id)
            # Linear: many in, few out or few in, few out
            if (in_deg >= 10 and out_deg <= 3) or (in_deg <= 3 and out_deg <= 3):
                result["flow_type"] = "linear"
                score = max(0, score - 10.0)  # reduce suspicion for linear flow
                result["findings"].append("Linear flow pattern (low suspicion)")
            else:
                result["flow_type"] = "mixed"
        else:
            result["flow_type"] = "linear"

    result["graph_score"] = round(min(100.0, (score / WEIGHT_GRAPH) * 100.0), 1)
    return result


def _find_short_loops(
    G: nx.DiGraph, source: str, max_depth: int = 5,
) -> List[List[str]]:
    """Find short loops (cycles) that include *source* using bounded DFS."""
    loops: List[List[str]] = []

    def dfs(current: str, path: List[str], depth: int):
        if depth > max_depth:
            return
        for neighbor in G.successors(current):
            if neighbor == source and len(path) >= BACKTRACK_MIN_DEPTH:
                loops.append(list(path))
            elif neighbor not in path and depth < max_depth:
                dfs(neighbor, path + [neighbor], depth + 1)

    if source in G:
        dfs(source, [source], 1)

    # Deduplicate (same loop can be found from different start points)
    unique = []
    seen_sets = []
    for loop in loops:
        s = frozenset(loop)
        if s not in seen_sets:
            seen_sets.append(s)
            unique.append(loop)

    return unique[:10]  # cap at 10


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — TIMING BEHAVIOR ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _step2_timing_behavior(
    account_id: str, df: pd.DataFrame,
) -> Dict[str, Any]:
    """Compute timing metrics for the account.

    Computes:
    - CV (Coefficient of Variation) of inter-transaction gaps
    - Burst detection (many txns in short window)
    - Off-hours transaction ratio
    - Automation pattern (same minute daily)

    Returns dict with metrics and timing_score (0–100).
    """
    result: Dict[str, Any] = {
        "cv": None,
        "cv_label": "unknown",
        "burst_detected": False,
        "burst_count": 0,
        "max_burst_size": 0,
        "off_hours_ratio": 0.0,
        "off_hours_count": 0,
        "automation_detected": False,
        "automation_pattern": None,
        "total_transactions": 0,
        "timing_score": 0.0,
        "findings": [],
    }

    # Get all transactions for this account
    mask = (df["sender_id"] == account_id) | (df["receiver_id"] == account_id)
    acct_df = df[mask].copy()

    if acct_df.empty:
        return result

    result["total_transactions"] = len(acct_df)
    timestamps = acct_df["timestamp"].sort_values()

    score = 0.0

    # ── CV calculation ────────────────────────────────────────────────────
    if len(timestamps) >= 3:
        intervals = timestamps.diff().dropna().dt.total_seconds().values
        mean_interval = np.mean(intervals)

        if mean_interval > 0:
            cv = float(np.std(intervals) / mean_interval)
            result["cv"] = round(cv, 4)

            if cv < CV_STABLE:
                result["cv_label"] = "stable"
                result["findings"].append(
                    f"Stable timing (CV={cv:.3f}) — merchant-like regularity"
                )
                # Stable = less suspicious for timing
            elif cv <= CV_MODERATE_UPPER:
                result["cv_label"] = "moderate"
                score += 10.0
                result["findings"].append(
                    f"Moderate timing variability (CV={cv:.3f})"
                )
            else:
                result["cv_label"] = "bursty"
                score += 25.0
                result["findings"].append(
                    f"Bursty/irregular timing (CV={cv:.3f}) — suspicious"
                )

    # ── Burst detection ───────────────────────────────────────────────────
    burst_window = pd.Timedelta(minutes=BURST_WINDOW_MINUTES)
    ts_values = timestamps.values
    bursts = []
    i = 0
    while i < len(ts_values):
        window_end = ts_values[i] + np.timedelta64(int(BURST_WINDOW_MINUTES), 'm')
        count = int(np.sum((ts_values >= ts_values[i]) & (ts_values <= window_end)))
        if count >= BURST_MIN_TXN:
            bursts.append(count)
            i += count  # skip past this burst
        else:
            i += 1

    if bursts:
        result["burst_detected"] = True
        result["burst_count"] = len(bursts)
        result["max_burst_size"] = max(bursts)
        score += min(20.0, 5.0 * len(bursts))
        result["findings"].append(
            f"{len(bursts)} burst(s) detected, max {max(bursts)} txns in {BURST_WINDOW_MINUTES}min"
        )

    # ── Off-hours detection ───────────────────────────────────────────────
    hours = pd.to_datetime(timestamps).dt.hour
    off_hours = ((hours < BUSINESS_HOUR_START) | (hours >= BUSINESS_HOUR_END)).sum()
    total = len(hours)
    if total > 0:
        off_ratio = off_hours / total
        result["off_hours_ratio"] = round(off_ratio, 3)
        result["off_hours_count"] = int(off_hours)

        if off_ratio > 0.5 and total >= 5:
            score += 10.0
            result["findings"].append(
                f"{off_ratio:.0%} transactions outside business hours ({BUSINESS_HOUR_START}:00–{BUSINESS_HOUR_END}:00)"
            )

    # ── Automation pattern detection ──────────────────────────────────────
    # Check if transactions occur at the exact same minute across different days
    if len(timestamps) >= 5:
        time_of_day = pd.to_datetime(timestamps).dt.hour * 60 + pd.to_datetime(timestamps).dt.minute
        counter = Counter(time_of_day.values)
        most_common_minute, most_common_count = counter.most_common(1)[0]

        if most_common_count >= 3 and most_common_count / len(timestamps) >= 0.3:
            h, m = divmod(int(most_common_minute), 60)
            result["automation_detected"] = True
            result["automation_pattern"] = f"{h:02d}:{m:02d}"
            score += 15.0
            result["findings"].append(
                f"Automation pattern: {most_common_count} transactions at {h:02d}:{m:02d} daily"
            )

    result["timing_score"] = round(min(100.0, (score / WEIGHT_TIMING) * 100.0), 1)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — DISTINCT AMOUNT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _step3_amount_analysis(
    account_id: str,
    df: pd.DataFrame,
    layering_accounts: Set[str],
    structuring_flagged: Set[str],
    structuring_details: Dict[str, dict],
    repeat_flagged: Set[str],
) -> Dict[str, Any]:
    """Analyze transaction amounts for suspicious patterns.

    Checks:
    - Are amounts highly repetitive? (e.g., 9999, 9999, 9999)
    - Are amounts just below AML threshold?
    - Are amounts gradually decreasing in chain? (layering)
    - Are amounts exact rounded values every time?

    Returns dict with metrics and amount_pattern_score (0–100).
    """
    result: Dict[str, Any] = {
        "repetitive_amounts": False,
        "most_repeated_amount": None,
        "repeat_count": 0,
        "below_threshold": False,
        "threshold_details": None,
        "layering_detected": False,
        "round_amounts": False,
        "round_amount_ratio": 0.0,
        "amount_variance": None,
        "natural_variance": False,
        "amount_pattern_score": 0.0,
        "findings": [],
    }

    # Get all outgoing amounts
    sent_mask = df["sender_id"] == account_id
    recv_mask = df["receiver_id"] == account_id
    all_mask = sent_mask | recv_mask
    acct_df = df[all_mask]

    if acct_df.empty:
        return result

    amounts = acct_df["amount"].values
    score = 0.0

    # ── Repetitive amounts ────────────────────────────────────────────────
    if len(amounts) >= REPEAT_MIN:
        rounded = np.round(amounts, 0)
        counter = Counter(rounded)
        most_common_amt, most_common_count = counter.most_common(1)[0]

        if most_common_count >= REPEAT_MIN:
            result["repetitive_amounts"] = True
            result["most_repeated_amount"] = float(most_common_amt)
            result["repeat_count"] = int(most_common_count)
            score += min(25.0, 8.0 * (most_common_count / len(amounts)) * 10)
            result["findings"].append(
                f"Repetitive amounts: ${most_common_amt:,.0f} appears {most_common_count}x"
            )

    # Also flag from the global repeat detection
    if account_id in repeat_flagged:
        if not result["repetitive_amounts"]:
            result["repetitive_amounts"] = True
            score += 10.0
            result["findings"].append("Flagged for amount repetition pattern")

    # ── Below AML threshold ───────────────────────────────────────────────
    if account_id in structuring_flagged:
        detail = structuring_details.get(account_id, {})
        result["below_threshold"] = True
        result["threshold_details"] = detail
        score += min(25.0, 15.0 + 2.0 * detail.get("count_below", 0))
        result["findings"].append(
            f"Structuring: {detail.get('count_below', 0)} transactions just below "
            f"${detail.get('threshold', 0):,.0f} threshold"
        )
    else:
        # Manual check for sent transactions
        sent_amounts = df[sent_mask]["amount"].values
        if len(sent_amounts) >= 3:
            for threshold in AML_THRESHOLDS:
                lower = threshold * (1 - BELOW_THRESHOLD_PCT)
                below = sent_amounts[(sent_amounts >= lower) & (sent_amounts < threshold)]
                if len(below) >= 3:
                    result["below_threshold"] = True
                    result["threshold_details"] = {
                        "threshold": threshold,
                        "count_below": int(len(below)),
                        "mean_amount": round(float(np.mean(below)), 2),
                    }
                    score += min(25.0, 15.0 + 2.0 * len(below))
                    result["findings"].append(
                        f"Structuring: {len(below)} sent amounts cluster below ${threshold:,.0f}"
                    )
                    break

    # ── Layering detection ────────────────────────────────────────────────
    if account_id in layering_accounts:
        result["layering_detected"] = True
        score += 20.0
        result["findings"].append(
            "Part of a layering chain (gradually decreasing amounts)"
        )

    # ── Round amount detection ────────────────────────────────────────────
    if len(amounts) >= 3:
        round_values = [100, 500, 1000, 5000, 10000]
        round_count = 0
        for amt in amounts:
            for rv in round_values:
                if abs(amt - round(amt / rv) * rv) <= ROUND_TOLERANCE:
                    round_count += 1
                    break

        round_ratio = round_count / len(amounts)
        result["round_amount_ratio"] = round(round_ratio, 3)
        if round_ratio > 0.7 and len(amounts) >= 5:
            result["round_amounts"] = True
            score += 10.0
            result["findings"].append(
                f"{round_ratio:.0%} of amounts are exact round values"
            )

    # ── Natural variance check ────────────────────────────────────────────
    if len(amounts) >= 3:
        cv = float(np.std(amounts) / np.mean(amounts)) if np.mean(amounts) > 0 else 0
        result["amount_variance"] = round(cv, 4)
        if cv > 0.5:
            result["natural_variance"] = True
            score = max(0, score - 10.0)  # natural variance reduces suspicion
            result["findings"].append(
                f"Amounts vary naturally (CV={cv:.3f}) — less suspicious"
            )

    result["amount_pattern_score"] = round(min(100.0, (score / WEIGHT_AMOUNT) * 100.0), 1)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — BEHAVIOR CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

def _step4_classify(
    account_id: str,
    G: nx.MultiDiGraph,
    simple_G: nx.DiGraph,
    df: pd.DataFrame,
    graph_result: Dict[str, Any],
    timing_result: Dict[str, Any],
    amount_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Classify account behavior into one of three transaction categories.

    MERCHANT:    Payments to registered businesses / service providers.
                 Predictable patterns (fixed/recurring amounts at regular intervals).
                 High in-degree, low CV, many distinct customers, business-hour activity.

    FRIEND:      Peer-to-peer transfers between individuals (splitting rent,
                 sharing bills, emergency money). Amounts and timing vary naturally,
                 no strict recurring pattern, no cycles or suspicious behavior.

    SUSPICIOUS:  Anonymous / potentially fraudulent payments. Repeated exact same
                 amounts, same-time automation, rapid back-and-forth transfers,
                 cyclic money movement (A→B→C→A), threshold avoidance, layering.

    Returns dict with classification, confidence, and reasoning.
    """
    result: Dict[str, Any] = {
        "classification": "UNKNOWN",
        "confidence": 0.0,
        "reasoning": [],
    }

    in_degree = 0
    out_degree = 0
    if account_id in simple_G:
        in_degree = simple_G.in_degree(account_id)
        out_degree = simple_G.out_degree(account_id)

    cv = timing_result.get("cv")
    cv_label = timing_result.get("cv_label", "unknown")
    cycle_detected = graph_result.get("cycle_detected", False)
    rapid = graph_result.get("rapid_forwarding", False)
    flow_type = graph_result.get("flow_type", "unknown")
    total_txns = timing_result.get("total_transactions", 0)
    off_hours_ratio = timing_result.get("off_hours_ratio", 0)

    # Scoring for each classification
    merchant_score = 0.0
    friend_score = 0.0
    suspicious_score = 0.0

    # ══════════════════════════════════════════════════════════════════════
    # MERCHANT signals — registered business / service provider
    # Predictable, fixed/recurring amounts, regular intervals, high in-degree
    # ══════════════════════════════════════════════════════════════════════

    # High in-degree = many customers paying this account (like a shop)
    if in_degree >= MERCHANT_MIN_IN_DEGREE:
        merchant_score += 30.0
        result["reasoning"].append(f"High in-degree ({in_degree}) — many incoming customers (merchant-like)")
    elif in_degree >= 20:
        merchant_score += 15.0
        result["reasoning"].append(f"Moderate in-degree ({in_degree}) — multiple payers")

    # No cycles — legitimate businesses don't have circular money flows
    if not cycle_detected:
        merchant_score += 15.0
    else:
        merchant_score -= 30.0  # cycles strongly disqualify merchant classification

    # Stable timing (low CV) — recurring subscriptions / regular purchases
    if cv is not None and cv < CV_STABLE:
        merchant_score += 25.0
        result["reasoning"].append(f"Stable timing (CV={cv:.3f}) — recurring/predictable pattern")

    # Receiver pattern: many in, few out (customers pay merchant, merchant rarely pays back)
    if in_degree >= 10 and out_degree <= 5:
        merchant_score += 15.0
        result["reasoning"].append("Many incoming, few outgoing — receiver/merchant pattern")

    # Business-hour activity
    if off_hours_ratio < 0.3:
        merchant_score += 10.0
        result["reasoning"].append("Transactions mostly during business hours")

    # Fixed/recurring amounts (low amount variance = subscription-like)
    if amount_result.get("repetitive_amounts") and not cycle_detected and not rapid:
        rep_count = amount_result.get("repeat_count", 0)
        if rep_count >= 5:
            merchant_score += 15.0
            result["reasoning"].append(
                f"Recurring fixed amount (${amount_result.get('most_repeated_amount', 0):,.0f} × {rep_count}) — subscription pattern"
            )

    # Round amounts common for merchants (pricing in round numbers)
    if amount_result.get("round_amounts") and not cycle_detected:
        merchant_score += 5.0

    # ══════════════════════════════════════════════════════════════════════
    # FRIEND signals — peer-to-peer / personal transfers
    # Variable amounts & timing, no recurring pattern, no cycles,
    # moderate degree, natural variance in behavior
    # ══════════════════════════════════════════════════════════════════════

    # No cycles — friends don't create circular money loops
    if not cycle_detected:
        friend_score += 15.0

    # No rapid forwarding — friends don't immediately relay money
    if not rapid:
        friend_score += 10.0

    # Natural amount variance — splitting bills creates varied amounts
    if amount_result.get("natural_variance"):
        friend_score += 20.0
        result["reasoning"].append("Natural amount variance — typical of personal transfers")

    # Moderate CV (not too regular, not too bursty) — personal needs vary
    if cv is not None and CV_STABLE <= cv <= CV_MODERATE_UPPER:
        friend_score += 15.0
        result["reasoning"].append(f"Moderate timing variability (CV={cv:.3f}) — personal pattern")

    # Low-to-moderate degree — individuals transact with a limited circle
    if in_degree <= 15 and out_degree <= 15:
        friend_score += 10.0
    if 2 <= (in_degree + out_degree) <= 20:
        friend_score += 5.0
        result["reasoning"].append(f"Limited transaction circle (in={in_degree}, out={out_degree})")

    # Not repetitive amounts — personal transfers don't repeat exact amounts
    if not amount_result.get("repetitive_amounts"):
        friend_score += 10.0

    # No structuring / threshold avoidance
    if not amount_result.get("below_threshold"):
        friend_score += 5.0

    # No automation
    if not timing_result.get("automation_detected"):
        friend_score += 5.0

    # Linear flow type
    if flow_type == "linear":
        friend_score += 5.0

    # Low transaction volume is typical for personal accounts
    if total_txns <= 20:
        friend_score += 10.0
        result["reasoning"].append(f"Low transaction volume ({total_txns}) — personal account")

    # Check for bidirectional transfers (friends often send back and forth)
    if account_id in simple_G:
        mutual = 0
        for succ in simple_G.successors(account_id):
            if simple_G.has_edge(succ, account_id):
                mutual += 1
        if mutual > 0 and mutual <= 5 and not cycle_detected:
            friend_score += 10.0
            result["reasoning"].append(f"Bidirectional transfers with {mutual} peer(s) — typical friend pattern")

    # ══════════════════════════════════════════════════════════════════════
    # SUSPICIOUS signals — anonymous / potentially fraudulent
    # Repeated exact amounts, same-time automation, rapid back-and-forth,
    # cyclic movement (A→B→C→A), threshold avoidance, layering
    # ══════════════════════════════════════════════════════════════════════

    # Cyclic money movement (A → B → C → A) — classic fraud/laundering
    if cycle_detected:
        suspicious_score += 30.0
        result["reasoning"].append(
            f"Cyclic money flow detected ({graph_result.get('cycle_count', 0)} cycle(s)) — A→B→C→A pattern"
        )

    # Rapid back-and-forth transfers — automated mule behavior
    if rapid:
        suspicious_score += 20.0
        result["reasoning"].append("Rapid back-and-forth transfers — automated relay behavior")

    # Bursty/irregular timing (high CV) — suspicious when combined
    if cv is not None and cv > CV_MODERATE_UPPER:
        suspicious_score += 15.0
        result["reasoning"].append(f"Bursty timing (CV={cv:.3f}) — irregular pattern")

    # Repeated exact same amount — structuring / bot-driven
    if amount_result.get("repetitive_amounts"):
        rep_count = amount_result.get("repeat_count", 0)
        # Only suspicious if combined with other red flags or very high repetition
        if cycle_detected or rapid or rep_count >= 5:
            suspicious_score += 15.0
            result["reasoning"].append(
                f"Repeated exact amount (${amount_result.get('most_repeated_amount', 0):,.0f} × {rep_count})"
            )
        elif rep_count >= 3:
            suspicious_score += 8.0

    # Transactions at same specific time repeatedly — automation pattern
    if timing_result.get("automation_detected"):
        suspicious_score += 15.0
        result["reasoning"].append(
            f"Automation pattern: transactions repeatedly at {timing_result.get('automation_pattern')} — bot-like"
        )

    # AML threshold avoidance (amounts just below reporting limits)
    if amount_result.get("below_threshold"):
        suspicious_score += 15.0
        result["reasoning"].append("Amounts cluster just below AML reporting threshold — structuring")

    # Layering chain (gradually decreasing amounts through hops)
    if amount_result.get("layering_detected"):
        suspicious_score += 15.0
        result["reasoning"].append("Layering chain — gradually decreasing amounts through hops")

    # Circular flow type
    if flow_type == "circular":
        suspicious_score += 10.0

    # Off-hours activity combined with other flags
    if off_hours_ratio > 0.6 and (cycle_detected or rapid or timing_result.get("automation_detected")):
        suspicious_score += 5.0
        result["reasoning"].append(f"Mostly off-hours activity ({off_hours_ratio:.0%}) combined with other red flags")

    # ── Pick the highest classification ───────────────────────────────────
    scores = {
        "MERCHANT": merchant_score,
        "FRIEND": friend_score,
        "SUSPICIOUS": suspicious_score,
    }

    best_class = max(scores, key=scores.get)
    best_score = scores[best_class]
    total_all = sum(scores.values())

    # If suspicious is within 10 pts of the best and has significant score, override
    if best_class != "SUSPICIOUS" and suspicious_score >= 30 and (best_score - suspicious_score) < 10:
        best_class = "SUSPICIOUS"
        best_score = suspicious_score

    confidence = round((best_score / max(total_all, 1)) * 100, 1)

    result["classification"] = best_class
    result["confidence"] = min(confidence, 99.0)
    result["all_scores"] = {k: round(v, 1) for k, v in scores.items()}

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5 — OUTPUT FORMAT
# ═══════════════════════════════════════════════════════════════════════════════

def _step5_build_output(
    account_id: str,
    graph_result: Dict[str, Any],
    timing_result: Dict[str, Any],
    amount_result: Dict[str, Any],
    classification: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the final structured output for the account.

    Output format:
    {
        "account_id": "",
        "classification": "",
        "risk_score": 0-100,
        "graph_score": "",
        "timing_score": "",
        "amount_pattern_score": "",
        "cycle_detected": true/false,
        "reasoning_summary": ""
    }
    """
    graph_score = graph_result.get("graph_score", 0.0)
    timing_score = timing_result.get("timing_score", 0.0)
    amount_score = amount_result.get("amount_pattern_score", 0.0)

    # Weighted composite risk score
    risk_score = round(
        (graph_score * WEIGHT_GRAPH +
         timing_score * WEIGHT_TIMING +
         amount_score * WEIGHT_AMOUNT) / (WEIGHT_GRAPH + WEIGHT_TIMING + WEIGHT_AMOUNT),
        1,
    )

    # Build reasoning summary
    all_findings = (
        graph_result.get("findings", []) +
        timing_result.get("findings", []) +
        amount_result.get("findings", []) +
        classification.get("reasoning", [])
    )
    # Deduplicate and limit
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f not in seen:
            seen.add(f)
            unique_findings.append(f)

    reasoning_summary = "; ".join(unique_findings[:8]) if unique_findings else "No significant patterns detected"

    # Determine risk label
    if risk_score >= 50:
        risk_label = "HIGH"
    elif risk_score >= 25:
        risk_label = "MEDIUM"
    else:
        risk_label = "LOW"

    return {
        "account_id": account_id,
        "classification": classification["classification"],
        "classification_confidence": classification["confidence"],
        "classification_scores": classification.get("all_scores", {}),
        "risk_score": risk_score,
        "risk_label": risk_label,
        "graph_score": graph_score,
        "timing_score": timing_score,
        "amount_pattern_score": amount_score,
        "cycle_detected": graph_result.get("cycle_detected", False),
        "reasoning_summary": reasoning_summary,
        # Detailed breakdown
        "details": {
            "graph": {
                "cycle_count": graph_result.get("cycle_count", 0),
                "flow_type": graph_result.get("flow_type", "unknown"),
                "rapid_forwarding": graph_result.get("rapid_forwarding", False),
                "rapid_event_count": graph_result.get("rapid_event_count", 0),
                "short_loops_count": len(graph_result.get("short_loops", [])),
            },
            "timing": {
                "cv": timing_result.get("cv"),
                "cv_label": timing_result.get("cv_label", "unknown"),
                "burst_detected": timing_result.get("burst_detected", False),
                "burst_count": timing_result.get("burst_count", 0),
                "off_hours_ratio": timing_result.get("off_hours_ratio", 0.0),
                "automation_detected": timing_result.get("automation_detected", False),
                "automation_pattern": timing_result.get("automation_pattern"),
            },
            "amount": {
                "repetitive_amounts": amount_result.get("repetitive_amounts", False),
                "most_repeated_amount": amount_result.get("most_repeated_amount"),
                "repeat_count": amount_result.get("repeat_count", 0),
                "below_threshold": amount_result.get("below_threshold", False),
                "layering_detected": amount_result.get("layering_detected", False),
                "round_amounts": amount_result.get("round_amounts", False),
                "round_amount_ratio": amount_result.get("round_amount_ratio", 0.0),
                "natural_variance": amount_result.get("natural_variance", False),
            },
        },
        "findings": unique_findings,
    }
