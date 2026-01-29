"""
Utility functions for Intelligence Aggregator
"""

import json
import re
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
import hashlib


def parse_ip_port(observable: str) -> Tuple[str, Optional[int], bool]:
    """
    Parse IP:port format from observable

    Args:
        observable: Observable string (e.g., "192.168.1.1:443" or "192.168.1.1")

    Returns:
        Tuple of (ip_or_observable, port_number or None, has_port_specified)

    Example:
        parse_ip_port("139.180.203.104:443") -> ("139.180.203.104", 443, True)
        parse_ip_port("139.180.203.104") -> ("139.180.203.104", None, False)
    """
    # Check if observable contains a colon (potential port)
    if ":" in observable:
        parts = observable.rsplit(":", 1)  # Split from right to handle IPv6 if needed
        potential_ip = parts[0]
        potential_port = parts[1]

        # Validate that second part is a port number
        try:
            port_num = int(potential_port)
            if 0 <= port_num <= 65535:
                # Validate that first part is an IP
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", potential_ip):
                    ip_parts = potential_ip.split(".")
                    if all(0 <= int(part) <= 255 for part in ip_parts):
                        return (potential_ip, port_num, True)
        except (ValueError, TypeError):
            pass

    # No valid port found, return original observable
    return (observable, None, False)


def classify_observable(observable: str) -> str:
    """Classify observable type (handles IP, IP:port, domain, URL, hash)"""
    # Check for IP:port format first
    if ":" in observable:
        parts = observable.rsplit(":", 1)
        potential_ip = parts[0]
        potential_port = parts[1]

        try:
            port_num = int(potential_port)
            if 0 <= port_num <= 65535:
                # Validate IP
                if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", potential_ip):
                    ip_parts = potential_ip.split(".")
                    if all(0 <= int(part) <= 255 for part in ip_parts):
                        return "IP:Port"
        except (ValueError, TypeError):
            pass

    # Check for plain IP
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", observable):
        parts = observable.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return "IP"

    if re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", observable, re.IGNORECASE):
        return "Domain"

    if re.match(r"^https?://", observable):
        return "URL"

    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", observable):
        length = len(observable)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"

    return "Unknown"


def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return timestamp


def get_threat_level(malicious: int, suspicious: int) -> str:
    """Determine threat level based on detection counts"""
    if malicious >= 10:
        return "🔴 Critical"
    elif malicious >= 5:
        return "🟠 High"
    elif malicious > 0 or suspicious >= 5:
        return "🟡 Medium"
    elif suspicious > 0:
        return "🔵 Low"
    else:
        return "🟢 Clean"


def get_threat_color(malicious: int, suspicious: int) -> str:
    """Get color code for threat level"""
    if malicious >= 10:
        return "#FF0000"  # Red
    elif malicious >= 5:
        return "#FF6600"  # Orange
    elif malicious > 0 or suspicious >= 5:
        return "#FFCC00"  # Yellow
    elif suspicious > 0:
        return "#0099FF"  # Blue
    else:
        return "#00CC00"  # Green


def extract_key_findings(results: Dict[str, Any]) -> List[str]:
    """Extract key findings from analysis results"""
    findings = []

    # VirusTotal findings
    if "VirusTotal" in results and "raw_data" in results["VirusTotal"]:
        vt = results["VirusTotal"]
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            findings.append(f"⚠️ VirusTotal: {malicious} vendors flagged as malicious")
        if suspicious > 0:
            findings.append(f"⚠️ VirusTotal: {suspicious} vendors flagged as suspicious")

    # Shodan findings
    if "Shodan" in results and "ports" in results["Shodan"]:
        shodan = results["Shodan"]
        ports = shodan.get("ports", [])
        if ports:
            findings.append(f"🔌 Shodan: {len(ports)} open ports detected ({', '.join(map(str, ports[:5]))})")
        if shodan.get("os"):
            findings.append(f"🖥️ Shodan: OS detected - {shodan['os']}")

    # OTX findings
    if "AlienVault OTX" in results and "pulses" in results["AlienVault OTX"]:
        pulses = results["AlienVault OTX"].get("pulses", [])
        if pulses:
            findings.append(f"🚨 OTX: Found in {len(pulses)} threat pulses")
            if len(pulses) > 0:
                findings.append(f"   Top threat: {pulses[0].get('name', 'Unknown')}")

    # AbuseIPDB findings
    if "AbuseIPDB" in results:
        abuse = results["AbuseIPDB"]
        score = abuse.get("abuse_confidence_score", 0)
        if score > 75:
            findings.append(f"🚫 AbuseIPDB: High abuse confidence ({score}%)")
        elif score > 25:
            findings.append(f"⚠️ AbuseIPDB: Moderate abuse confidence ({score}%)")


    # Hunter.io findings
    if "Hunter.io" in results:
        hunter = results["Hunter.io"]

        # Email findings for domain search
        if hunter.get("type") == "domain":
            emails_found = hunter.get("emails_found", 0)
            if emails_found > 0:
                findings.append(f"📧 Hunter.io: {emails_found} emails discovered for domain")

            # Company identification
            company_info = hunter.get("company_info", {})
            if company_info and "name" in company_info:
                findings.append(f"🏢 Hunter.io: Company identified - {company_info.get('name')}")

        # Email verification findings
        elif hunter.get("type") == "email":
            verification = hunter.get("verification", {})
            status = verification.get("status", "")
            if status == "valid":
                findings.append(f"✅ Hunter.io: Email address is valid and deliverable")
            elif status == "invalid":
                findings.append(f"❌ Hunter.io: Email address is invalid")

            # Person enrichment
            person_info = hunter.get("person", {})
            if person_info and "first_name" in person_info:
                name = f"{person_info.get('first_name', '')} {person_info.get('last_name', '')}".strip()
                if name:
                    findings.append(f"👤 Hunter.io: Person identified - {name}")


    # Malware Bazaar findings
    if "Malware Bazaar" in results:
        mb = results["Malware Bazaar"]

        # Malware detected
        if mb.get("query_status") == "ok" and mb.get("type") == "hash":
            if mb.get("signature"):
                findings.append(f"🦠 Malware Bazaar: MALWARE DETECTED - {mb.get('signature')}")

            tags = mb.get("tags", [])
            if tags and isinstance(tags, list):
                findings.append(f"🏷️ Malware Bazaar: Tags - {', '.join(tags[:5])}")

            # Intelligence data
            intelligence = mb.get("intelligence", {})
            if intelligence:
                if intelligence.get("clamav"):
                    findings.append(f"🔴 Malware Bazaar: ClamAV Signature - {intelligence.get('clamav')}")
                downloads = intelligence.get("downloads")
                if downloads and int(downloads) > 0:
                    findings.append(f"📥 Malware Bazaar: {downloads} downloads from MalwareBazaar")

        # Sample collections found
        elif mb.get("type") in ["tag_query", "signature_query"]:
            sample_count = mb.get("sample_count", 0)
            query_type = "tag" if mb.get("type") == "tag_query" else "signature"
            if sample_count > 0:
                findings.append(f"📋 Malware Bazaar: {sample_count} malware samples found for {query_type} '{mb.get('observable')}'")


    # ThreatFox findings - ENHANCED VERSION
    if "ThreatFox" in results:
        tf = results["ThreatFox"]

        if tf.get("query_status") == "ok" and tf.get("ioc_count", 0) > 0:
            iocs = tf.get("iocs", [])

            # Check for malware-related IOCs
            malware_iocs = [ioc for ioc in iocs if ioc.get("malware")]
            if malware_iocs:
                malware_families = set(ioc.get('malware_printable', ioc.get('malware')) for ioc in malware_iocs)
                findings.append(f"⚠️ ThreatFox: {len(malware_families)} malware families detected - {', '.join(list(malware_families)[:3])}")

            # Check for botnet C&C servers
            botnet_iocs = [ioc for ioc in iocs if ioc.get("threat_type") == "botnet_cc"]
            if botnet_iocs:
                findings.append(f"🤖 ThreatFox: {len(botnet_iocs)} botnet C&C server(s) detected")

            # Check for phishing
            phishing_iocs = [ioc for ioc in iocs if ioc.get("threat_type") == "phishing"]
            if phishing_iocs:
                findings.append(f"🎣 ThreatFox: {len(phishing_iocs)} phishing IOC(s) detected")

            # Check for malware distribution
            malware_dist_iocs = [ioc for ioc in iocs if ioc.get("threat_type") == "malware_download"]
            if malware_dist_iocs:
                findings.append(f"📥 ThreatFox: {len(malware_dist_iocs)} malware distribution IOC(s) detected")

            # Overall IOC count with high confidence
            high_confidence_iocs = [ioc for ioc in iocs if ioc.get('confidence_level', 0) >= 75]
            if high_confidence_iocs:
                findings.append(f"🔴 ThreatFox: {len(high_confidence_iocs)} high-confidence IOC(s) (≥75%)")

            # Average confidence
            if iocs:
                avg_confidence = sum([ioc.get('confidence_level', 0) for ioc in iocs]) / len(iocs)
                if avg_confidence >= 50:
                    findings.append(f"📊 ThreatFox: Average confidence {avg_confidence:.1f}%")

        elif tf.get("query_status") == "skipped":
            findings.append(f"⚠️ ThreatFox: Query skipped - {tf.get('message', 'Port required for IP searches')}")

        elif tf.get("ioc_count", 0) == 0:
            findings.append("✅ ThreatFox: No threats found in database")


    # YARAify findings
    if "YARAify" in results:
        yaraify = results["YARAify"]

        if yaraify.get("query_status") == "ok":
            # Check for malware detection
            if yaraify.get("signature"):
                findings.append(f"🦠 YARAify: MALWARE DETECTED - {yaraify.get('signature')}")

            # Check for YARA rules
            yara_count = yaraify.get("yara_rules", 0)
            if yara_count > 0:
                findings.append(f"🔍 YARAify: {yara_count} YARA rules matched")

                # Show top YARA rules if available
                yara_rules = yaraify.get("yara_rules_list", [])   # <-- THE FIX
                if yara_rules and isinstance(yara_rules, list):
                    top_rules = [r.get("rule_name", str(r)) for r in yara_rules[:3]]
                    findings.append(f"   Top YARA: {', '.join(top_rules)}")

            # Check for malware family
            malware_family = yaraify.get("malware_family")
            if malware_family:
                findings.append(f"🏷️ YARAify: Malware family identified - {malware_family}")

            # Check for ClamAV signature
            clamav = yaraify.get("clamav_signature")
            if clamav:
                findings.append(f"🔴 YARAify: ClamAV Signature - {clamav}")

            # Check for comments
            comments = yaraify.get("comments", 0)
            if comments > 0:
                findings.append(f"💬 YARAify: {comments} community comments")

        elif yaraify.get("query_status") == "hash_not_found":
            findings.append("✅ YARAify: Hash not found in database")

    return findings if findings else ["✅ No major threats detected"]


def format_results_for_export(results: Dict[str, Any], observable: str) -> str:
    """Format results as JSON for export"""
    export_data = {
        "query_date": datetime.now().isoformat(),
        "observable": observable,
        "observable_type": classify_observable(observable),
        "results": {}
    }

    for source, data in results.items():
        # Remove raw_data for cleaner export
        cleaned = {k: v for k, v in data.items() if k != "raw_data"}
        export_data["results"][source] = cleaned

    return json.dumps(export_data, indent=2, default=str)


def create_summary_report(results: Dict[str, Any], observable: str) -> str:
    """Create a text summary report"""
    report = f"""
================================================================================
                        INTELLIGENCE AGGREGATOR REPORT
================================================================================

Observable: {observable}
Type: {classify_observable(observable)}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

================================================================================
                               KEY FINDINGS
================================================================================

"""

    findings = extract_key_findings(results)
    for finding in findings:
        report += f"\n{finding}"

    report += "\n\n" + "="*80 + "\n"
    report += "                            DETAILED RESULTS\n"
    report += "="*80 + "\n"

    for source, data in results.items():
        if "error" not in data:
            report += f"\n[{source}]\n"
            report += "-" * 40 + "\n"

            # Special handling for ThreatFox with IOCs
            if source == "ThreatFox" and data.get("iocs"):
                report += f"  Query Status: {data.get('query_status', 'N/A')}\n"
                report += f"  IOC Count: {data.get('ioc_count', 0)}\n"
                report += f"  Observable: {data.get('observable', 'N/A')}\n"
                report += "\n  IOCs Details:\n"

                for idx, ioc in enumerate(data.get("iocs", []), 1):
                    report += f"\n    IOC {idx}:\n"
                    report += f"      IOC: {ioc.get('ioc', 'N/A')}\n"
                    report += f"      Type: {ioc.get('ioc_type_desc', ioc.get('ioc_type', 'N/A'))}\n"
                    report += f"      Threat Type: {ioc.get('threat_type_desc', ioc.get('threat_type', 'N/A'))}\n"
                    report += f"      Malware: {ioc.get('malware_printable', ioc.get('malware', 'N/A'))}\n"
                    report += f"      Confidence: {ioc.get('confidence_level', 'N/A')}%\n"
                    report += f"      Reporter: {ioc.get('reporter', 'N/A')}\n"
                    report += f"      First Seen: {ioc.get('first_seen', 'N/A')}\n"
                    report += f"      Last Seen: {ioc.get('last_seen', 'Still Active')}\n"
                    if ioc.get("tags"):
                        tags = ioc.get("tags", [])
                        report += f"      Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n"
                    if ioc.get("reference"):
                        report += f"      Reference: {ioc.get('reference')}\n"
            # YARAify results
            elif source == "YARAify" and data.get("query_status") == "ok":
                report += f"  Query Status: {data.get('query_status', 'N/A')}\n"
                report += f"  File Name: {data.get('file_name', 'N/A')}\n"
                report += f"  File Size: {data.get('file_size', 'N/A')} bytes\n"
                report += f"  File Type: {data.get('file_type', 'N/A')}\n"
                report += f"  Signature: {data.get('signature', 'N/A')}\n"
                report += f"  Malware Family: {data.get('malware_family', 'N/A')}\n"
                report += f"  YARA Rules: {data.get('yara_rules', 0)}\n"
                report += f"  First Seen: {data.get('first_seen', 'N/A')}\n"
                report += f"  Last Seen: {data.get('last_seen', 'N/A')}\n"
                report += f"  Reporter: {data.get('reporter', 'N/A')}\n"
                if data.get("tags"):
                    tags = data.get("tags", [])
                    report += f"  Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n"
            else:
                # Display key data points (skip raw_data and complex objects)
                for key, value in data.items():
                    if key not in ["raw_data", "pulses", "reports", "services", "urls", "scans", "intelligences", "iocs"] and value is not None:
                        if isinstance(value, (str, int, float, bool)):
                            report += f"  {key.replace('_', ' ').title()}: {value}\n"
                        elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], (str, int)):
                            report += f"  {key.replace('_', ' ').title()}: {', '.join(map(str, value[:10]))}\n"

    report += "\n" + "="*80 + "\n"

    return report


def save_report(report: str, filename: str = None) -> str:
    """Save report to file"""
    if filename is None:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, 'w') as f:
        f.write(report)

    return filename


def get_analytics_data(results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract analytics data from results"""
    analytics = {
        "sources_queried": len([s for s in results if "error" not in results[s]]),
        "sources_failed": len([s for s in results if "error" in results[s]]),
        "malicious_detections": 0,
        "suspicious_detections": 0,
        "threat_level": "Clean",
    }

    # Aggregate threat data
    for source, data in results.items():
        if "malicious" in data:
            analytics["malicious_detections"] += data.get("malicious", 0)
        if "suspicious" in data:
            analytics["suspicious_detections"] += data.get("suspicious", 0)

    # Determine overall threat level
    malicious = analytics["malicious_detections"]
    suspicious = analytics["suspicious_detections"]

    if malicious >= 10:
        analytics["threat_level"] = "🔴 Critical"
    elif malicious >= 5:
        analytics["threat_level"] = "🟠 High"
    elif malicious > 0 or suspicious >= 5:
        analytics["threat_level"] = "🟡 Medium"
    elif suspicious > 0:
        analytics["threat_level"] = "🔵 Low"
    else:
        analytics["threat_level"] = "🟢 Clean"

    return analytics


# ============================================================================
# BATCH PROCESSING FUNCTIONS
# ============================================================================

def parse_indicators_from_file(file_content: str) -> List[str]:
    """
    Parse indicators from uploaded file content
    Handles both .txt and .csv formats
    """
    lines = file_content.strip().split('\n')
    indicators = []

    for line in lines:
        # Skip empty lines and comments
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Handle CSV format (take first column)
        if ',' in line:
            indicator = line.split(',')[0].strip()
        else:
            indicator = line

        # Validate and add
        if indicator and len(indicator) > 0:
            indicators.append(indicator)

    return indicators


def validate_batch_indicators(indicators: List[str]) -> tuple:
    """
    Validate indicators in batch
    Returns (valid_indicators, invalid_indicators, summary)
    """
    valid = []
    invalid = []

    for indicator in indicators:
        obs_type = classify_observable(indicator)
        if obs_type != "Unknown":
            valid.append({
                "indicator": indicator,
                "type": obs_type
            })
        else:
            invalid.append({
                "indicator": indicator,
                "reason": "Unrecognized format"
            })

    summary = {
        "total": len(indicators),
        "valid": len(valid),
        "invalid": len(invalid),
        "validation_rate": f"{(len(valid) / len(indicators) * 100):.1f}%" if indicators else "0%"
    }

    return valid, invalid, summary


def get_batch_threat_summary(batch_results: Dict[str, Dict]) -> tuple:
    """
    Create summary statistics for batch results
    Returns (summary_dict, threat_breakdown_dict)
    """
    summary = {
        "total_analyzed": len(batch_results),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "clean": 0,
        "errors": 0,
    }

    threat_breakdown = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "clean": [],
        "error": []
    }

    for indicator, result in batch_results.items():
        # Check if there's an error in any of the sources
        has_error = all("error" in source_result for source_result in result.values())

        if has_error:
            summary["errors"] += 1
            threat_breakdown["error"].append(indicator)
        else:
            # Calculate threat level for this indicator
            analytics = get_analytics_data(result)
            threat_level = analytics.get("threat_level", "🟢 Clean")

            if "🔴 Critical" in threat_level:
                summary["critical"] += 1
                threat_breakdown["critical"].append(indicator)
            elif "🟠 High" in threat_level:
                summary["high"] += 1
                threat_breakdown["high"].append(indicator)
            elif "🟡 Medium" in threat_level:
                summary["medium"] += 1
                threat_breakdown["medium"].append(indicator)
            elif "🔵 Low" in threat_level:
                summary["low"] += 1
                threat_breakdown["low"].append(indicator)
            else:
                summary["clean"] += 1
                threat_breakdown["clean"].append(indicator)

    return summary, threat_breakdown


def export_batch_results_json(batch_results: Dict[str, Dict], indicators_metadata: List[Dict]) -> str:
    """Export batch results as JSON"""
    export_data = {
        "export_date": datetime.now().isoformat(),
        "total_indicators": len(batch_results),
        "indicators": {}
    }

    for indicator, result in batch_results.items():
        # Get metadata
        metadata = next((m for m in indicators_metadata if m["indicator"] == indicator), {})

        # Calculate analytics for this indicator
        analytics = get_analytics_data(result)

        export_data["indicators"][indicator] = {
            "type": metadata.get("type", "Unknown"),
            "threat_level": analytics.get("threat_level", "Unknown"),
            "malicious_detections": analytics.get("malicious_detections", 0),
            "suspicious_detections": analytics.get("suspicious_detections", 0),
            "sources_queried": analytics.get("sources_queried", 0),
            "results": {}
        }

        # Add individual source results
        for source, source_data in result.items():
            cleaned = {k: v for k, v in source_data.items() if k != "raw_data"}
            export_data["indicators"][indicator]["results"][source] = cleaned

    return json.dumps(export_data, indent=2, default=str)


def export_batch_results_txt(batch_results: Dict[str, Dict], indicators_metadata: List[Dict]) -> str:
    """Export batch results as comprehensive text report"""
    report = f"""
{'='*80}
                    BATCH INTELLIGENCE AGGREGATOR REPORT
{'='*80}

Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Total Indicators: {len(batch_results)}

{'='*80}
                              SUMMARY STATISTICS
{'='*80}

"""

    summary, threat_breakdown = get_batch_threat_summary(batch_results)

    report += f"""
Critical Threats:   {summary['critical']} indicators
High Threats:       {summary['high']} indicators
Medium Threats:     {summary['medium']} indicators
Low Threats:        {summary['low']} indicators
Clean:              {summary['clean']} indicators
Errors:             {summary['errors']} indicators

{'='*80}
                         DETAILED RESULTS BY INDICATOR
{'='*80}

"""

    # Add detailed report for each indicator
    for idx, (indicator, results) in enumerate(batch_results.items(), 1):
        metadata = next((m for m in indicators_metadata if m["indicator"] == indicator), {})
        analytics = get_analytics_data(results)

        report += f"\n{'='*80}\n"
        report += f"INDICATOR {idx}/{len(batch_results)}: {indicator}\n"
        report += f"{'='*80}\n\n"
        report += f"Type: {metadata.get('type', 'Unknown')}\n"
        report += f"Threat Level: {analytics.get('threat_level', 'Unknown')}\n"
        report += f"Malicious Detections: {analytics.get('malicious_detections', 0)}\n"
        report += f"Suspicious Detections: {analytics.get('suspicious_detections', 0)}\n"
        report += f"Sources Queried: {analytics.get('sources_queried', 0)}\n"
        report += "\n" + "-"*80 + "\n"
        report += "KEY FINDINGS:\n"
        report += "-"*80 + "\n"

        findings = extract_key_findings(results)
        for finding in findings:
            report += f"{finding}\n"

        report += "\n" + "-"*80 + "\n"
        report += "DETAILED RESULTS BY SOURCE:\n"
        report += "-"*80 + "\n\n"

        # Add results from each source
        for source, data in results.items():
            if "error" in data:
                report += f"[{source}]: ERROR - {data['error']}\n\n"
            else:
                report += f"[{source}]\n"

                # Special handling for ThreatFox with IOCs
                if source == "ThreatFox" and data.get("iocs"):
                    report += f"  Query Status: {data.get('query_status', 'N/A')}\n"
                    report += f"  IOC Count: {data.get('ioc_count', 0)}\n"
                    report += f"  Observable: {data.get('observable', 'N/A')}\n"
                    report += "\n  IOCs Details:\n"

                    for idx, ioc in enumerate(data.get("iocs", []), 1):
                        report += f"\n    IOC {idx}:\n"
                        report += f"      IOC: {ioc.get('ioc', 'N/A')}\n"
                        report += f"      Type: {ioc.get('ioc_type_desc', ioc.get('ioc_type', 'N/A'))}\n"
                        report += f"      Threat Type: {ioc.get('threat_type_desc', ioc.get('threat_type', 'N/A'))}\n"
                        report += f"      Malware: {ioc.get('malware_printable', ioc.get('malware', 'N/A'))}\n"
                        report += f"      Confidence: {ioc.get('confidence_level', 'N/A')}%\n"
                        report += f"      Reporter: {ioc.get('reporter', 'N/A')}\n"
                        report += f"      First Seen: {ioc.get('first_seen', 'N/A')}\n"
                        report += f"      Last Seen: {ioc.get('last_seen', 'Still Active')}\n"
                        if ioc.get("tags"):
                            tags = ioc.get("tags", [])
                            report += f"      Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n"
                        if ioc.get("reference"):
                            report += f"      Reference: {ioc.get('reference')}\n"
                    report += "\n"
                # YARAify results
                elif source == "YARAify" and data.get("query_status") == "ok":
                    report += f"  Query Status: {data.get('query_status', 'N/A')}\n"
                    report += f"  File Name: {data.get('file_name', 'N/A')}\n"
                    report += f"  File Size: {data.get('file_size', 'N/A')} bytes\n"
                    report += f"  File Type: {data.get('file_type', 'N/A')}\n"
                    report += f"  Signature: {data.get('signature', 'N/A')}\n"
                    report += f"  Malware Family: {data.get('malware_family', 'N/A')}\n"
                    report += f"  YARA Rules: {data.get('yara_rules', 0)}\n"
                    report += f"  First Seen: {data.get('first_seen', 'N/A')}\n"
                    report += f"  Last Seen: {data.get('last_seen', 'N/A')}\n"
                    report += f"  Reporter: {data.get('reporter', 'N/A')}\n"
                    if data.get("tags"):
                        tags = data.get("tags", [])
                        report += f"  Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n"
                else:
                    for key, value in data.items():
                        if key not in ["raw_data", "pulses", "reports", "services", "urls", "scans", "intelligences", "iocs"] and value is not None:
                            if isinstance(value, (str, int, float, bool)):
                                report += f"  {key.replace('_', ' ').title()}: {value}\n"
                            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], (str, int)):
                                report += f"  {key.replace('_', ' ').title()}: {', '.join(map(str, value[:10]))}\n"
                report += "\n"

        report += "\n"

    report += "="*80 + "\n"
    report += "END OF BATCH REPORT\n"
    report += "="*80 + "\n"

    return report


def create_individual_batch_reports(batch_results: Dict[str, Dict], indicators_metadata: List[Dict]) -> Dict[str, str]:
    """
    Create individual text reports for each indicator in the batch
    Returns dict with indicator as key and report text as value
    """
    individual_reports = {}

    for indicator, results in batch_results.items():
        report = create_summary_report(results, indicator)
        individual_reports[indicator] = report

    return individual_reports
