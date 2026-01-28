"""
Configuration management
"""

import os
from typing import Tuple
from dotenv import load_dotenv

# Force reload of .env file with override every time this module is imported
load_dotenv(override=True)


class ConfigMeta(type):
    """Metaclass to handle dynamic attribute access for Config"""
    
    def __getattr__(cls, name):
        """Get attribute values dynamically from environment"""
        if name == "VIRUSTOTAL_API_KEY":
            return os.getenv("VIRUSTOTAL_API_KEY", "")
        elif name == "SHODAN_API_KEY":
            return os.getenv("SHODAN_API_KEY", "")
        elif name == "OTX_API_KEY":
            return os.getenv("OTX_API_KEY", "")
        elif name == "IPINFO_API_KEY":
            return os.getenv("IPINFO_API_KEY", "")
        elif name == "ABUSEIPDB_API_KEY":
            return os.getenv("ABUSEIPDB_API_KEY", "")
        elif name == "URLSCAN_API_KEY":
            return os.getenv("URLSCAN_API_KEY", "")
        elif name == "URLHAUS_API_KEY":
            return os.getenv("URLHAUS_API_KEY", "")
        elif name == "IPDETECTIVE_API_KEY":
            return os.getenv("IPDETECTIVE_API_KEY", "")
        elif name == "GETIPINTEL_CONTACT":
            return os.getenv("GETIPINTEL_CONTACT", "")
        elif name == "RANSOMWARE_LIVE_API_KEY":
            return os.getenv("RANSOMWARE_LIVE_API_KEY", "")
        elif name == "HUNTER_API_KEY":
            return os.getenv("HUNTER_API_KEY", "")
        elif name == "MALWARE_BAZAAR_API_KEY":
            return os.getenv("MALWARE_BAZAAR_API_KEY", "")
        elif name == "THREATFOX_API_KEY":
            return os.getenv("THREATFOX_API_KEY", "")
        elif name == "REQUEST_TIMEOUT":
            return int(os.getenv("REQUEST_TIMEOUT", "10"))
        elif name == "CACHE_ENABLED":
            return os.getenv("CACHE_ENABLED", "true").lower() == "true"
        elif name == "CACHE_TTL":
            return int(os.getenv("CACHE_TTL", "3600"))
        raise AttributeError(f"'{cls.__name__}' has no attribute '{name}'")


class Config(metaclass=ConfigMeta):
    """Application configuration - reads from environment dynamically"""
    
    PAGE_TITLE = "Intelligence Aggregator"
    PAGE_ICON = "🔍"
    LAYOUT = "wide"

    # Supported intelligence sources - update when adding new integrations
    SUPPORTED_INTELLIGENCE_SOURCES = [
        "VirusTotal",
        "Shodan",
        "AlienVault OTX",
        "IPInfo",
        "AbuseIPDB",
        "URLscan",
        "URLhaus",
        "IP Detective",
        "GetIPIntel",
        "Ransomware.live",
        "Hunter.io",
        "Malware Bazaar",
        "ThreatFox",
    ]
    
    @classmethod
    def get_active_apis(cls) -> dict:
        """Get list of configured APIs - reads fresh from environment each time"""
        apis = {}
        
        if os.getenv("VIRUSTOTAL_API_KEY", ""):
            apis["VirusTotal"] = True
        if os.getenv("SHODAN_API_KEY", ""):
            apis["Shodan"] = True
        if os.getenv("OTX_API_KEY", ""):
            apis["AlienVault OTX"] = True
        if os.getenv("IPINFO_API_KEY", ""):
            apis["IPInfo"] = True
        if os.getenv("ABUSEIPDB_API_KEY", ""):
            apis["AbuseIPDB"] = True
        if os.getenv("URLSCAN_API_KEY", ""):
            apis["URLscan"] = True
        
        # URLhaus is always available (no API key required)
        apis["URLhaus"] = True
        
        if os.getenv("IPDETECTIVE_API_KEY", ""):
            apis["IP Detective"] = True
        
        if os.getenv("GETIPINTEL_CONTACT", ""):
            apis["GetIPIntel"] = True
        
        if os.getenv("RANSOMWARE_LIVE_API_KEY", ""):
            apis["Ransomware.live"] = True
        if os.getenv("HUNTER_API_KEY", ""):
            apis["Hunter.io"] = True
        if os.getenv("MALWARE_BAZAAR_API_KEY", ""):
            apis["Malware Bazaar"] = True
        if os.getenv("THREATFOX_API_KEY", ""):
            apis["ThreatFox"] = True
        
        return apis
    
    @classmethod
    def debug_config(cls):
        """Debug function to show all API keys (masked)"""
        debug_info = {
            "VIRUSTOTAL_API_KEY": "✅" if os.getenv("VIRUSTOTAL_API_KEY", "") else "❌",
            "SHODAN_API_KEY": "✅" if os.getenv("SHODAN_API_KEY", "") else "❌",
            "OTX_API_KEY": "✅" if os.getenv("OTX_API_KEY", "") else "❌",
            "IPINFO_API_KEY": "✅" if os.getenv("IPINFO_API_KEY", "") else "❌",
            "ABUSEIPDB_API_KEY": "✅" if os.getenv("ABUSEIPDB_API_KEY", "") else "❌",
            "URLSCAN_API_KEY": "✅" if os.getenv("URLSCAN_API_KEY", "") else "❌",
            "URLHAUS_API_KEY": "✅" if os.getenv("URLHAUS_API_KEY", "") else "❌",
            "IPDETECTIVE_API_KEY": "✅" if os.getenv("IPDETECTIVE_API_KEY", "") else "❌",
            "GETIPINTEL_CONTACT": "✅" if os.getenv("GETIPINTEL_CONTACT", "") else "❌",
            "RANSOMWARE_LIVE_API_KEY": "✅" if os.getenv("RANSOMWARE_LIVE_API_KEY", "") else "❌",
            "HUNTER_API_KEY": "✅" if os.getenv("HUNTER_API_KEY", "") else "❌",
            "MALWARE_BAZAAR_API_KEY": "✅" if os.getenv("MALWARE_BAZAAR_API_KEY", "") else "❌",
            "THREATFOX_API_KEY": "✅" if os.getenv("THREATFOX_API_KEY", "") else "❌",
        }
        return debug_info
    
    @classmethod
    def validate_config(cls):
        """Validate configuration"""
        active_apis = cls.get_active_apis()
        
        if not active_apis:
            return False, "❌ No API keys configured. Please set API keys in .env file."
        
        return True, f"✅ {len(active_apis)} API sources configured"
