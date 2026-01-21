# X-10 ThreatFusion

**Intelligence Command Platform | 10 Sources. Total Control.**

![giphy](https://github.com/user-attachments/assets/d5270fb7-6a73-4343-b508-4e5064308c52)

## Overview

X-10 ThreatFusion is a unified threat intelligence platform that correlates indicators across 10 premier security data sources, providing comprehensive threat analysis from a single command center.

## Key Features

- **Multi-Source Intelligence**: Integrates VirusTotal, Shodan, AlienVault OTX, IPInfo, AbuseIPDB, URLhaus, URLscan, IP Detective, GetIPIntel, and Ransomware.live
- **Dual Analysis Modes**: Single indicator analysis or batch processing
- **Advanced Ransomware Tracking**: Two-phase analysis - group intelligence → victim domain correlation
- **Real-Time Correlation**: Parallel API queries with automated threat scoring
- **Flexible Export**: JSON and TXT format support

## Use Cases

- Incident response & threat hunting
- IOC validation & OSINT investigations
- APT & ransomware group tracking
- Bulk indicator enrichment

## Tech Stack

- **Frontend**: Streamlit (Python)
- **Backend**: Python with modular API clients
- **Data Processing**: JSON-based aggregation & correlation
- **Architecture**: Session-based state management with parallel query execution

## How It Works

1. **Input** - Enter IP, domain, hash, or ransomware group
2. **Query** - Select and query 1-10 intelligence sources simultaneously
3. **Correlate** - Automated threat scoring and cross-source analysis
4. **Analyze** - For ransomware groups: extract victims → query victim domains across all sources
5. **Export** - Download results in JSON or TXT format

## Project Structure
```
x10-threatfusion/
├── apis/           # Modular API client classes
├── utils/          # Data processing helpers
├── app.py          # Main Streamlit application
```


Contributions welcome! Please open an issue or submit a pull request.

---

## Screenshots

### Main Dashboard
<img width="1345" height="539" alt="dashboard_1" src="https://github.com/user-attachments/assets/1e7a3af0-aaba-462e-9928-8c688b16cceb" />
<img width="1353" height="558" alt="dashboard_2" src="https://github.com/user-attachments/assets/ca786aa6-cf09-4581-ac4e-da43cb48d1b6" />

### Observable Analysis
<img width="951" height="458" alt="IP_analysis" src="https://github.com/user-attachments/assets/3171eb55-b81b-4612-8b67-5978cf11dc65" />
<img width="920" height="506" alt="Ip_analysis2" src="https://github.com/user-attachments/assets/50cafb42-c3c1-459b-a012-63109ffca284" />
<img width="956" height="424" alt="ip_analysis3" src="https://github.com/user-attachments/assets/3e09f35d-bffc-4b97-a5da-8fe0089677ac" />

### Ransomware Group Tracking
<img width="976" height="460" alt="TG1" src="https://github.com/user-attachments/assets/0936382d-ec18-4918-84ae-2d37db69448b" />
<img width="924" height="503" alt="TG2" src="https://github.com/user-attachments/assets/f7a8b0fc-e1ed-482f-acbf-6701fc647e71" />
<img width="832" height="345" alt="TG3" src="https://github.com/user-attachments/assets/305c483b-1571-48d0-aff5-c520ecadfa0c" />
<img width="898" height="395" alt="TG4" src="https://github.com/user-attachments/assets/a783b7cc-e575-42e5-9d73-edbb5120fe8f" />
<img width="936" height="453" alt="TG5" src="https://github.com/user-attachments/assets/3c318ad1-9a9d-4bc6-b961-efb47518fbba" />
<img width="996" height="525" alt="TG6" src="https://github.com/user-attachments/assets/68d68a90-2f2e-45c6-8ef1-21c433c5e3c9" />

### Batch Processing
<img width="1003" height="484" alt="batch1" src="https://github.com/user-attachments/assets/c6461789-817b-41b6-a1c8-e5a14ea2d4cd" />
<img width="896" height="453" alt="batch2" src="https://github.com/user-attachments/assets/be584fd1-0895-4a55-a721-93e6b7e1e685" />
<img width="901" height="529" alt="batch3" src="https://github.com/user-attachments/assets/3a85ec25-e5cf-41c6-9445-c0da21ce10d3" />
<img width="918" height="449" alt="batch4" src="https://github.com/user-attachments/assets/2fc9ccc6-c0f1-4f87-aaf4-5951b5521ebb" />
<img width="923" height="489" alt="batch5" src="https://github.com/user-attachments/assets/4550ce57-a24a-4e60-af0e-255b34fc9a16" />

### Export Results
<img width="956" height="331" alt="final1" src="https://github.com/user-attachments/assets/1f6ab5a9-b6c5-4927-ac11-1047062a0bf0" />
<img width="1366" height="659" alt="final2" src="https://github.com/user-attachments/assets/2779ce85-9d4a-443f-afb8-f9f65e3cf9a4" />
<img width="772" height="646" alt="final3" src="https://github.com/user-attachments/assets/290f4b61-38d5-44a3-b346-5b564adc499b" />
<img width="1037" height="593" alt="final4" src="https://github.com/user-attachments/assets/f238fbd5-5e9b-48ef-a3d6-80b48751042b" />


**X-10 ThreatFusion** - Command your intelligence, dominate the threat landscape.




