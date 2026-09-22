"""
CyberForge — YARA Scanning Engine
Compiles all YARA rules from the rules directory and scans submitted samples.
Returns structured match results with confidence scoring.
"""
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger("cyberforge.yara")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python not installed. YARA scanning disabled.")


@dataclass
class YARAMatch:
    rule_name: str
    namespace: str          # which .yar file it came from
    family: str
    severity: str
    description: str
    mitre_ids: list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def confidence(self) -> str:
        """Derive confidence from severity."""
        return {
            "CRITICAL": "HIGH",
            "HIGH":     "HIGH",
            "MEDIUM":   "MEDIUM",
            "LOW":      "LOW",
        }.get(self.severity, "MEDIUM")

    def to_dict(self) -> dict:
        return {
            "rule":         self.rule_name,
            "namespace":    self.namespace,
            "family":       self.family,
            "severity":     self.severity,
            "confidence":   self.confidence(),
            "description":  self.description,
            "mitre":        self.mitre_ids,
            "hits":         self.matched_strings[:20],
            "tags":         self.tags,
        }


@dataclass
class YARAScanResult:
    matches: list[YARAMatch] = field(default_factory=list)
    total_matches: int = 0
    scanned: bool = False
    error: Optional[str] = None
    highest_severity: str = "CLEAN"

    def to_dict(self) -> dict:
        return {
            "scanned":          self.scanned,
            "total_matches":    self.total_matches,
            "highest_severity": self.highest_severity,
            "error":            self.error,
            "matches":          [m.to_dict() for m in self.matches],
        }


class YARAScanner:
    """
    Singleton-style YARA scanner. Compiles all .yar files in rules_dir
    once at startup and reuses the compiled ruleset for performance.
    """

    _compiled_rules = None
    _rules_path: Optional[Path] = None

    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self._load_rules()

    def _load_rules(self):
        """Compile all .yar files in the rules directory into one ruleset."""
        if not YARA_AVAILABLE:
            return

        yar_files = list(self.rules_dir.glob("*.yar")) + \
                    list(self.rules_dir.glob("*.yara"))

        if not yar_files:
            logger.warning(f"No YARA rule files found in {self.rules_dir}")
            return

        filepaths = {}
        for yar in yar_files:
            ns = yar.stem   # use filename (without ext) as namespace
            filepaths[ns] = str(yar)

        try:
            YARAScanner._compiled_rules = yara.compile(filepaths=filepaths)
            YARAScanner._rules_path = self.rules_dir
            logger.info(f"YARA rules compiled: {len(yar_files)} files loaded from {self.rules_dir}")
        except yara.SyntaxError as e:
            logger.error(f"YARA compile error: {e}")
            YARAScanner._compiled_rules = None

    def reload_rules(self):
        """Force re-compile rules (call after adding/updating rule files)."""
        YARAScanner._compiled_rules = None
        self._load_rules()

    def scan_file(self, file_path: Path, timeout: int = 60) -> YARAScanResult:
        """
        Scan a file against all loaded YARA rules.

        Args:
            file_path: Path to the file to scan
            timeout: Maximum seconds for scanning (anti-DoS)

        Returns:
            YARAScanResult with all matches
        """
        result = YARAScanResult()

        if not YARA_AVAILABLE:
            result.error = "YARA engine not available (install yara-python)"
            return result

        if YARAScanner._compiled_rules is None:
            result.error = "No YARA rules loaded"
            return result

        if not file_path.exists():
            result.error = f"File not found: {file_path}"
            return result

        try:
            raw_matches = YARAScanner._compiled_rules.match(
                str(file_path),
                timeout=timeout
            )
            result.scanned = True

            severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
            highest = 0

            for match in raw_matches:
                meta = match.meta or {}

                sev = meta.get("severity", "MEDIUM").upper()
                severity_rank_val = severity_rank.get(sev, 2)
                if severity_rank_val > highest:
                    highest = severity_rank_val

                # Extract matched string values
                hit_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            decoded = instance.matched_data.decode("utf-8", errors="replace")[:80]
                            hit_strings.append(decoded.strip())
                        except Exception:
                            pass

                # Parse MITRE IDs from meta
                mitre_raw = meta.get("mitre", "")
                mitre_ids = [m.strip() for m in mitre_raw.split(",") if m.strip()]

                yara_match = YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    family=meta.get("family", "Unknown"),
                    severity=sev,
                    description=meta.get("description", ""),
                    mitre_ids=mitre_ids,
                    matched_strings=list(set(hit_strings))[:15],
                    tags=list(match.tags),
                )
                result.matches.append(yara_match)

            result.total_matches = len(result.matches)
            sev_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "CLEAN"}
            result.highest_severity = sev_map.get(highest, "CLEAN")

        except yara.TimeoutError:
            result.error = f"YARA scan timed out after {timeout}s"
            result.scanned = False
        except Exception as e:
            result.error = f"YARA scan error: {str(e)}"
            logger.error(f"YARA scan error on {file_path}: {e}")

        return result

    def scan_bytes(self, data: bytes, timeout: int = 30) -> YARAScanResult:
        """Scan bytes directly (for memory forensics)."""
        result = YARAScanResult()

        if not YARA_AVAILABLE or YARAScanner._compiled_rules is None:
            result.error = "YARA engine not ready"
            return result

        try:
            raw_matches = YARAScanner._compiled_rules.match(
                data=data,
                timeout=timeout
            )
            result.scanned = True
            result.total_matches = len(raw_matches)

            for match in raw_matches:
                meta = match.meta or {}
                result.matches.append(YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    family=meta.get("family", "Unknown"),
                    severity=meta.get("severity", "MEDIUM").upper(),
                    description=meta.get("description", ""),
                ))

        except Exception as e:
            result.error = str(e)

        return result
