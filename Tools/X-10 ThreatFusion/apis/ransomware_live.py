"""
Ransomware.live API integration - Ransomware intelligence and threat data
"""

import logging
from typing import Dict, Any, List
import requests
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class RansomwareLiveAPI(BaseAPIClient):
    """Ransomware.live API client for ransomware intelligence"""

    BASE_URL = "https://api.ransomware.live"

    def __init__(self, api_key: str, timeout: int = 15):
        """Initialize Ransomware.live API client
        
        Args:
            api_key: Ransomware.live API key
            timeout: Request timeout in seconds (default: 15)
        """
        super().__init__(api_key, timeout)
        # Public API doesn't require auth header for basic queries
        self.public_headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0"
        }

    def _safe_request(self, url: str, headers: dict = None, expect_json: bool = True, retries: int = 3, backoff: float = 1.0, allow_redirects: bool = True):
        """Perform requests.get with retries and robust JSON/text handling.

        Returns parsed JSON when expect_json is True and valid, otherwise returns text.
        On repeated failures returns None.
        """
        headers = headers or {}
        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request error for {url} (attempt {attempt}/{retries}): {e}")
                if attempt < retries:
                    time_sleep = backoff * attempt
                    try:
                        import time
                        time.sleep(time_sleep)
                    except Exception:
                        pass
                    continue
                return None

            if resp.status_code != 200:
                logger.debug(f"Non-200 response for {url}: {resp.status_code}")
                # Do not retry on 4xx, but retry on 5xx once
                if 500 <= resp.status_code < 600 and attempt < retries:
                    try:
                        import time
                        time.sleep(backoff * attempt)
                    except Exception:
                        pass
                    continue
                return None

            if expect_json:
                try:
                    return resp.json()
                except ValueError as e:
                    logger.debug(f"JSON decode error for {url} (attempt {attempt}/{retries}): {e}")
                    # Try small wait and retry
                    if attempt < retries:
                        try:
                            import time
                            time.sleep(backoff * attempt)
                        except Exception:
                            pass
                        continue
                    return None
            else:
                try:
                    return resp.text
                except Exception as e:
                    logger.debug(f"Error reading text response for {url}: {e}")
                    return None

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze observable for ransomware-related intelligence
        
        Args:
            observable: Domain, IP, hash, or company name
            
        Returns:
            Analysis results
        """
        obs_type = self._classify_observable(observable)
        
        # Search for victims by name, domain, or any term
        results = self._search_victims(observable)
        
        # If observable looks like a domain/company name, also search for groups
        if obs_type in ["Domain", "URL", "Unknown"] or "." in observable:
            results["associated_groups"] = self._search_groups(observable)
        else:
            results["associated_groups"] = []
        
        return results

    def analyze_group(self, group_name: str) -> Dict[str, Any]:
        """
        Analyze a threat group for comprehensive ransomware intelligence
        Returns all available data like Ransomware.live website
        
        Args:
            group_name: Name of the ransomware group
            
        Returns:
            Comprehensive group analysis with stats, metadata, and victims
        """
        response = {
            "source": "Ransomware.live",
            "group_name": group_name,
            "type": "ransomware_group_analysis",
            "group_info": {},
            "recent_victims": [],
            "victim_domains": [],
            "threat_level": "unknown",
            "is_malicious": False,
            "malicious": 0,
            "suspicious": 0,
            # New comprehensive fields
            "status": "Active",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "",
                "last_victim_date": "",
                "inactive_days": 0,
                "avg_delay_days": 0.0,
                "infostealer_percentage": 0.0
            },
            "metadata": {
                "known_locations": 0,
                "ransom_notes": 0,
                "tools_used": 0,
                "vulnerabilities_exploited": 0,
                "ttps_matrix": 0,
                "negotiation_chats": 0,
                "yara_rules": 0,
                "iocs_count": 0
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {}
        }
        
        # Get comprehensive group data
        comprehensive_data = self._get_comprehensive_group_data(group_name)
        
        # Merge comprehensive data into response
        response.update(comprehensive_data)
        
        # Normalize/merge nested lists into metadata to keep display logic compatible
        try:
            meta = response.setdefault("metadata", {})
            # Copy common list fields from top-level into metadata if missing
            for fld in ["known_locations_list", "ransom_notes_list", "tools_used_list", "vulnerabilities_list", "ttps_list", "negotiation_chats_list", "yara_rules_list", "iocs_list"]:
                if fld not in meta or meta.get(fld) is None:
                    if fld in response:
                        meta[fld] = response.get(fld) or []

            # Ensure counts exist
            meta.setdefault("known_locations", len(meta.get("known_locations_list", [])))
            meta.setdefault("ransom_notes", len(meta.get("ransom_notes_list", [])))
            meta.setdefault("tools_used", len(meta.get("tools_used_list", [])))
            meta.setdefault("vulnerabilities_exploited", len(meta.get("vulnerabilities_list", [])))
            meta.setdefault("ttps_matrix", len(meta.get("ttps_list", [])))
            meta.setdefault("negotiation_chats", len(meta.get("negotiation_chats_list", [])))
            meta.setdefault("yara_rules", len(meta.get("yara_rules_list", [])))
            meta.setdefault("iocs_count", len(meta.get("iocs_list", [])))

            # Ensure targets structure exists
            if "targets" not in response or response.get("targets") is None:
                response["targets"] = {"top_sectors": [], "top_countries": [], "sector_distribution": {}, "country_distribution": {}}
        except Exception:
            # Keep original behavior on error
            pass
        
        # Get victims for this specific group
        victims = self._get_victims_for_group(group_name)
        response["recent_victims"] = victims
        
        # Extract victim domains for correlation (deduplicated)
        victim_domains = set()
        for victim in victims:
            if "website" in victim and victim["website"]:
                victim_domains.add(victim["website"])
            if "name" in victim and victim["name"] != "N/A":
                victim_domains.add(victim["name"])
        
        response["victim_domains"] = list(victim_domains)[:20]  # Limit to 20 for Phase 2
        response["suspicious"] = len(victims)
        response["is_malicious"] = True if victims else False
        # Set threat level based on victim data - "not applicable" if no data found
        if len(victims) == 0:
            response["threat_level"] = "not applicable"
        elif len(victims) >= 100:
            response["threat_level"] = "critical"
        elif len(victims) >= 10:
            response["threat_level"] = "high"
        else:
            response["threat_level"] = "medium"
        
        return response

    def _get_comprehensive_group_data(self, group_name: str) -> Dict[str, Any]:
        """
        Get comprehensive group data from Ransomware.live API and website scraping
        
        Step 1: Calls /groups API endpoint for group metadata (NOT /api/groups redirect)
        Step 2: Scrapes website for victim data (not available in JSON API)
        
        Industry-grade approach combining API + web scraping when APIs are incomplete
        """
        comprehensive_data = {
            "status": "Unknown",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "Unknown",
                "last_victim_date": "Unknown",
                "inactive_days": 0,
                "avg_delay_days": "N/A",
                "infostealer_percentage": 0.0
            },
            "metadata": {
                "known_locations": 0,
                "known_locations_list": [],
                "ransom_notes": 0,
                "ransom_notes_list": [],
                "tools_used": 0,
                "tools_used_list": [],
                "vulnerabilities_exploited": 0,
                "vulnerabilities_list": [],
                "ttps_matrix": 0,
                "ttps_list": [],
                "negotiation_chats": 0,
                "negotiation_chats_list": [],
                "yara_rules": 0,
                "yara_rules_list": [],
                "iocs_count": 0
            },
            "targets": {
                "top_sectors": [],
                "top_countries": [],
                "sector_distribution": {},
                "country_distribution": {}
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {},
            "victim_domains": [],
            "iocs_list": [],
            "total_victims": 0
        }
        
        group_lower = group_name.lower().strip()
        
        try:
            # STEP 1: Fetch from /groups API endpoint (NOT /api/groups - that's a redirect)
            logger.info(f"Fetching data for {group_name} from Ransomware.live...")
            
            try:
                url = f"{self.BASE_URL}/groups"
                headers = {
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
                
                groups = self._safe_request(url, headers=headers, expect_json=True, retries=3, backoff=1.0)

                if groups:
                    try:
                        
                        if isinstance(groups, list):
                            # Search for matching group in API data
                            for group in groups:
                                if isinstance(group, dict):
                                    group_name_api = group.get("name", "").lower().strip()
                                    
                                    if group_lower == group_name_api:
                                        logger.info(f"✓ Found {group_name} in /groups API endpoint")
                                        
                                        # Extract locations (known_locations)
                                        locations = group.get("locations", [])
                                        known_locs_list = []
                                        for loc in locations:
                                            if isinstance(loc, dict):
                                                fqdn = loc.get("fqdn", "")
                                                if fqdn:
                                                    known_locs_list.append(fqdn)
                                        
                                        # Extract tools info (preserve tactic structure)
                                        tools_list = {}
                                        tools_data = group.get("tools", [])
                                        if tools_data and isinstance(tools_data, list) and len(tools_data) > 0:
                                            tool_dict = tools_data[0]
                                            if isinstance(tool_dict, dict):
                                                for tactic, tool_names in tool_dict.items():
                                                    if isinstance(tool_names, list):
                                                        tools_list[tactic] = tool_names
                                        
                                        comprehensive_data = {
                                            "status": group.get("status", "Unknown"),
                                            "description": group.get("description", ""),
                                            "history": group.get("history", group.get("background", "")),
                                            "statistics": {
                                                "total_victims": 0,  # Will be updated from website
                                                "first_victim_date": "Unknown",  # Will be updated from website
                                                "last_victim_date": "Unknown",  # Will be updated from website
                                                "inactive_days": self._calculate_inactive_days(group.get("last_activity", "")),
                                                "avg_delay_days": "N/A",  # Will be updated from website
                                                "infostealer_percentage": 0.0  # Will be updated from website
                                            },
                                            "metadata": {
                                                "known_locations": len(known_locs_list),
                                                "known_locations_list": known_locs_list,
                                                "ransom_notes": group.get("ransom_notes_count", 0),
                                                "ransom_notes_list": group.get("ransom_notes", []) if isinstance(group.get("ransom_notes", []), list) else [],
                                                "tools_used": len(tools_list),
                                                "tools_used_list": tools_list,
                                                "vulnerabilities_exploited": group.get("cves_count", group.get("vulnerabilities_count", 0)),
                                                "vulnerabilities_list": group.get("cves", []) if isinstance(group.get("cves", []), list) else [],
                                                "ttps_matrix": group.get("ttps_count", group.get("tactics_count", 0)),
                                                "negotiation_chats": group.get("chats_count", 0),
                                                "yara_rules": group.get("yara_rules_count", 0),
                                                "iocs_count": group.get("iocs_count", 0)
                                            },
                                            "active_regions": group.get("active_regions", []),
                                            "initial_access_vectors": group.get("initial_access_vectors", []),
                                            "tools_used_list": tools_list,
                                            "cves": group.get("exploited_cves", []),
                                            "related_groups": group.get("related_groups", []),
                                            "external_links": group.get("external_links", {}),
                                            "victim_domains": [],
                                            "iocs_list": [],
                                            "total_victims": 0,
                                            "targets": {
                                                "top_sectors": [],
                                                "top_countries": [],
                                                "sector_distribution": {},
                                                "country_distribution": {}
                                            }
                                        }
                                        break
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Error parsing API response: {e}")
                        pass
            except requests.exceptions.RequestException as e:
                logger.debug(f"API endpoint /groups failed: {e}")
            
            # STEP 2: Fetch victim data from website (victims NOT available in JSON API)
            logger.info(f"Fetching victim data from website for {group_name}...")
            try:
                # Use www subdomain to avoid redirect
                website_url = f"https://www.ransomware.live/group/{group_lower}"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                
                html = self._safe_request(website_url, headers=headers, expect_json=False, retries=3, backoff=1.0, allow_redirects=True)

                if html:
                    try:
                        from bs4 import BeautifulSoup
                        import re

                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Initialize all values
                        victims_count = 0
                        victim_domains = []
                        first_date = "Unknown"
                        last_date = "Unknown"
                        inactive_days = 0
                        avg_delay = "N/A"
                        infostealer_pct = 0.0
                        locations_count = 0
                        ransom_notes_count = 0
                        tools_count = "Unknown"
                        vulnerabilities_count = 0
                        ttps_count = 0
                        chats_count = 0
                        yara_count = 0
                        iocs_count = 0
                        iocs_list = []
                        
                        # STEP 2A: Extract statistics from h4 tags in statistics boxes
                        stats_containers = soup.find_all('div', class_='border-start')
                        for container in stats_containers:
                            label = container.find('h6')
                            value = container.find('h3') or container.find('h4')
                            if label and value:
                                label_text = label.get_text().strip().lower()
                                value_text = value.get_text().strip()
                                
                                if 'victims' in label_text:
                                    try:
                                        victims_count = int(value_text)
                                    except:
                                        victims_count = 0
                                elif 'first discovered' in label_text:
                                    first_date = value_text if value_text != "Unknown" else "Unknown"
                                elif 'last discovered' in label_text:
                                    last_date = value_text if value_text != "Unknown" else "Unknown"
                                elif 'inactive' in label_text:
                                    try:
                                        inactive_days = int(value_text)
                                    except:
                                        inactive_days = 0
                                elif 'avg delay' in label_text:
                                    avg_delay = value_text
                                elif 'infostealer' in label_text:
                                    try:
                                        # Extract percentage value
                                        match = re.search(r'(\d+\.?\d*)', value_text)
                                        if match:
                                            infostealer_pct = float(match.group(1))
                                    except:
                                        infostealer_pct = 0.0
                        
                        # STEP 2B: Extract metadata counts from span tags
                        for span in soup.find_all('span'):
                            text = span.get_text().strip()
                            
                            if 'Known Locations' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    locations_count = int(match.group(1))
                            elif 'Ransom Notes' in text and '(' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    ransom_notes_count = int(match.group(1))
                            elif 'Tools Used' in text:
                                if 'Available' in text:
                                    tools_count = "Available"
                                else:
                                    match = re.search(r'\((\d+)\)', text)
                                    if match:
                                        tools_count = int(match.group(1))
                            elif 'Vulnerabilities' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    vulnerabilities_count = int(match.group(1))
                            elif 'TTPs' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    ttps_count = int(match.group(1))
                            elif 'Negotiation Chats' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    chats_count = int(match.group(1))
                            elif 'YARA' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    yara_count = int(match.group(1))
                            elif 'Indicators of Compromise' in text or 'IoCs' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    iocs_count = int(match.group(1))
                            elif text == str(victims_count) and victims_count > 0:
                                # Already handled above
                                pass
                        
                        # STEP 2C: Extract IoCs if available
                        if iocs_count > 0:
                            iocs_section = soup.find(id='iocs-section')
                            if iocs_section:
                                # Extract IoC items (domains, IPs, hashes)
                                for item in iocs_section.find_all(['li', 'tr', 'div']):
                                    text = item.get_text().strip()
                                    if text and len(text) > 3:  # Filter out short texts
                                        iocs_list.append(text)
                        
                        # STEP 2D: Extract victim domains from href="/id/" links
                        for link in soup.find_all('a', href=True):
                            href = link.get('href', '')
                            if '/id/' in href and '#infostealer' not in href:
                                victim_text = link.get_text().strip()
                                if victim_text:
                                    victim_domains.append(victim_text)
                        
                        # Remove duplicates while preserving order
                        victim_domains = list(dict.fromkeys(victim_domains))
                        
                        # STEP 2E: Extract DETAILED information from SPECIFIC section IDs ONLY
                        
                        # Extract Known Locations from locations-section table
                        locations_list = []
                        locations_section = soup.find('div', id='locations-section')
                        if locations_section:
                            for row in locations_section.find_all('tr')[1:]:  # Skip header
                                cols = row.find_all('td')
                           
