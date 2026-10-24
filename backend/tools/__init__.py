"""LangChain tool wrappers. The logic lives in plain functions so it's easy to test."""

from langchain_core.tools import tool

from tools.attack_mapper import map_to_attack as _map_to_attack
from tools.intel import file_hash_reputation, ip_reputation


@tool
def check_ip_reputation(ip: str) -> dict:
    """Look up an IP address's abuse reputation (AbuseIPDB): abuse confidence score 0-100,
    country, ISP, usage type, report count and whether it is a Tor exit. Private/internal
    addresses return no reputation data."""
    return ip_reputation(ip)


@tool
def check_file_hash(sha256: str) -> dict:
    """Check whether a SHA-256 file hash is known malware (VirusTotal): detection ratio,
    verdict (malicious/suspicious/clean) and malware family if known."""
    return file_hash_reputation(sha256)


@tool
def map_to_attack(description: str) -> dict:
    """Find the closest MITRE ATT&CK techniques for a short description of the observed
    attacker behavior (e.g. 'many failed logins for one account from one IP'). Returns the
    top 5 candidate technique IDs with names, tactics and similarity scores."""
    return _map_to_attack(description)


TOOLS = [check_ip_reputation, check_file_hash, map_to_attack]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}
