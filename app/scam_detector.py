import sys
import json
import re
from typing import List, Tuple

# --- CONFIGURATION ---
keywords = {
    "high_risk": ["otp", "cvv", "password", "bank account", "lottery", "winner", "urgent", "pay tm", "gpay", "phonepe"],
    "medium_risk": ["click here", "verify", "update", "expired", "blocked", "refund", "sir", "madam", "kyc"]
}

THRESHOLD = 50


def analyze_message(message: str, current_total_score: int) -> Tuple[int, List[str], str]:
    """
    Returns: (score_added, evidence_list, state)
    state is "passive" or "agent_handoff"
    """
    score_increment = 0
    evidence: List[str] = []
    message_lower = (message or "").lower()

    # KEYWORD CHECK
    for word in keywords["high_risk"]:
        if word in message_lower:
            score_increment += 20
            evidence.append(f"High risk keyword: '{word}'")

    for word in keywords["medium_risk"]:
        if word in message_lower:
            score_increment += 10
            evidence.append(f"Medium risk keyword: '{word}'")

    # REGEX PATTERNS
    # Detects any 10-digit number (Phone/Mobile)
    if re.search(r"\b\d{10}\b", message or ""):
        score_increment += 15
        evidence.append("Pattern match: 10-digit number detected")

    # Detects UPI IDs (simple pattern)
    if re.search(r"[\w\.-]+@[\w\.-]+", message or ""):
        score_increment += 25
        evidence.append("Pattern match: UPI ID detected")

    new_total_score = int(current_total_score) + score_increment

    state = "passive"
    if new_total_score >= THRESHOLD:
        state = "agent_handoff"

    return score_increment, evidence, state


def analyze_message_json(message: str, current_total_score: int) -> dict:
    """Helper for CLI/testing: returns the full JSON structure."""
    score_added, evidence, state = analyze_message(message, current_total_score)
    return {
        "score_added": score_added,
        "total_score": int(current_total_score) + int(score_added),
        "state": state,
        "evidence": evidence
    }


if __name__ == "__main__":
    try:
        incoming_message = sys.argv[1]
        try:
            previous_score = int(sys.argv[2])
        except (IndexError, ValueError):
            previous_score = 0

        result = analyze_message_json(incoming_message, previous_score)
        print(json.dumps(result))

    except Exception as e:
        # Failsafe JSON so server doesn't crash
        print(json.dumps({
            "error": str(e),
            "score_added": 0,
            "total_score": 0,
            "state": "passive",
            "evidence": []
        }))
