from collections import Counter
from difflib import SequenceMatcher
from typing import Dict, List
import re

from config import ALERT_CONFIG, CORRELATION_MIN_PLATFORMS, CORRELATION_MIN_SIMILARITY


def _normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def _compact_username(username: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _normalize_username(username))


def _active_platforms(result: Dict) -> List[str]:
    profile_status = (result.get("profile_status") or {}) if isinstance(result, dict) else {}
    return sorted([platform for platform, info in profile_status.items() if info.get("exists")])


def _profile_found_pct(result: Dict) -> float:
    profile_status = (result.get("profile_status") or {}) if isinstance(result, dict) else {}
    if not profile_status:
        return 0.0
    found_count = sum(1 for info in profile_status.values() if info.get("exists"))
    return round(found_count / len(profile_status) * 100.0, 1)


def suggest_account_correlations(scans: List[Dict]) -> List[Dict]:
    correlations: List[Dict] = []
    normalized_scans = []

    for scan in scans:
        username = _normalize_username(scan.get("username", ""))
        platforms = set(scan.get("active_platforms") or _active_platforms(scan))
        if not username or not platforms:
            continue
        normalized_scans.append({"username": username, "platforms": platforms})

    for left_idx, left in enumerate(normalized_scans):
        for right in normalized_scans[left_idx + 1:]:
            common_platforms = sorted(left["platforms"] & right["platforms"])
            if len(common_platforms) < CORRELATION_MIN_PLATFORMS:
                continue

            union_size = len(left["platforms"] | right["platforms"])
            platform_similarity = len(common_platforms) / union_size if union_size else 0.0
            username_similarity = SequenceMatcher(
                None,
                _compact_username(left["username"]),
                _compact_username(right["username"]),
            ).ratio()
            similarity_score = round((platform_similarity * 0.7) + (username_similarity * 0.3), 3)

            if similarity_score < CORRELATION_MIN_SIMILARITY:
                continue

            confidence = "High" if similarity_score >= 0.9 else "Medium" if similarity_score >= 0.8 else "Low"
            correlations.append(
                {
                    "account1": left["username"],
                    "account2": right["username"],
                    "common_platforms": common_platforms,
                    "platform_similarity": round(platform_similarity, 3),
                    "username_similarity": round(username_similarity, 3),
                    "similarity_score": similarity_score,
                    "confidence": confidence,
                }
            )

    correlations.sort(key=lambda item: item["similarity_score"], reverse=True)
    return correlations[:50]


def detect_account_pattern(scans: List[Dict]) -> Dict:
    usernames = [_normalize_username(scan.get("username", "")) for scan in scans]
    usernames = [username for username in usernames if username]

    prefix_counter: Counter = Counter()
    suffix_counter: Counter = Counter()
    token_counter: Counter = Counter()
    platform_counter: Counter = Counter()

    for scan in scans:
        username = _normalize_username(scan.get("username", ""))
        if len(username) >= 3:
            prefix_counter[username[:3]] += 1
            suffix_counter[username[-3:]] += 1

        for token in username.replace("-", "_").split("_"):
            if len(token) >= 3:
                token_counter[token] += 1

        for platform in scan.get("active_platforms") or _active_platforms(scan):
            platform_counter[platform] += 1

    naming_patterns: List[str] = []
    for label, counter in (("prefix", prefix_counter), ("suffix", suffix_counter), ("token", token_counter)):
        for value, count in counter.most_common(5):
            if count >= 2:
                naming_patterns.append(f"{label}:{value} ({count}x)")

    return {
        "naming_patterns": naming_patterns[:10],
        "platform_preferences": platform_counter.most_common(10),
        "total_scans": len(scans),
        "unique_usernames": len(set(usernames)),
    }


def generate_alerts(scan_id: int, result: Dict) -> List[Dict]:
    del scan_id
    alerts: List[Dict] = []
    risk = (result.get("risk_assessment") or {}) if isinstance(result, dict) else {}
    risk_score = float(risk.get("score") or 0.0)
    risk_level = str(risk.get("level") or "Low")
    found_pct = _profile_found_pct(result)
    github_data = (result.get("github_api") or {}) if isinstance(result, dict) else {}
    followers = int(github_data.get("followers") or 0)
    active_platforms = _active_platforms(result)

    if found_pct >= float(ALERT_CONFIG.get("min_found_pct_threshold", 50.0)):
        severity = "HIGH" if found_pct >= 75 else "MEDIUM"
        alerts.append(
            {
                "type": "WIDE_PLATFORM_FOOTPRINT",
                "severity": severity,
                "message": f"Presenza elevata rilevata: {found_pct:.1f}% profili trovati su {len(active_platforms)} piattaforme.",
            }
        )

    if risk_score >= 70:
        alerts.append(
            {
                "type": "HIGH_RISK_SCORE",
                "severity": "HIGH",
                "message": f"Risk score elevato: {risk_score:.1f}/100 ({risk_level}).",
            }
        )
    elif risk_score >= 50:
        alerts.append(
            {
                "type": "ELEVATED_RISK_SCORE",
                "severity": "MEDIUM",
                "message": f"Risk score moderato-alto: {risk_score:.1f}/100 ({risk_level}).",
            }
        )

    if ALERT_CONFIG.get("high_follower_threshold") and followers >= int(ALERT_CONFIG["high_follower_threshold"]):
        alerts.append(
            {
                "type": "HIGH_FOLLOWER_COUNT",
                "severity": "MEDIUM",
                "message": f"GitHub mostra {followers} follower, sopra la soglia configurata.",
            }
        )

    if len(active_platforms) >= 8:
        alerts.append(
            {
                "type": "MULTI_PLATFORM_PRESENCE",
                "severity": "LOW",
                "message": f"Presenza distribuita su molte piattaforme: {', '.join(active_platforms[:8])}.",
            }
        )

    return alerts


def compare_scan_results(previous_result: Dict, current_result: Dict) -> Dict:
    previous_platforms = set(_active_platforms(previous_result))
    current_platforms = set(_active_platforms(current_result))

    previous_risk = float(((previous_result.get("risk_assessment") or {}).get("score") or 0.0))
    current_risk = float(((current_result.get("risk_assessment") or {}).get("score") or 0.0))
    previous_pct = _profile_found_pct(previous_result)
    current_pct = _profile_found_pct(current_result)

    previous_followers = int(((previous_result.get("github_api") or {}).get("followers") or 0))
    current_followers = int(((current_result.get("github_api") or {}).get("followers") or 0))

    return {
        "added_platforms": sorted(current_platforms - previous_platforms),
        "removed_platforms": sorted(previous_platforms - current_platforms),
        "unchanged_platforms": sorted(previous_platforms & current_platforms),
        "risk_delta": round(current_risk - previous_risk, 1),
        "found_pct_delta": round(current_pct - previous_pct, 1),
        "followers_delta": current_followers - previous_followers,
        "previous_risk": previous_risk,
        "current_risk": current_risk,
        "previous_found_pct": previous_pct,
        "current_found_pct": current_pct,
    }