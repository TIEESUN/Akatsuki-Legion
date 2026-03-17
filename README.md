# X-10 ThreatFusion

**Intelligence Command Platform | 10 Sources. Total Control.**
![ec00cb73-9dee-407d-a7e5-4ae0be057591 (1)](https://github.com/user-attachments/assets/fd375fde-e75d-4b90-b02c-fd8f7a6e1b08)


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
<img width="934" height="494" alt="TG1" src="https://github.com/user-attachments/assets/2292853f-4c25-4697-8357-4ce117c3c5a7" />
<img width="928" height="529" alt="TG2" src="https://github.com/user-attachments/assets/9931cc5c-9cce-41ec-ba75-f025a669d279" />
<img width="812" height="291" alt="TG3" src="https://github.com/user-attachments/assets/10a720d4-fbda-4567-ae59-89b37ee206db" />
<img width="860" height="382" alt="TG4" src="https://github.com/user-attachments/assets/8cb0d746-582d-4bf7-9694-945883c4eb82" />
<img width="910" height="385" alt="TG5" src="https://github.com/user-attachments/assets/cda57742-2e5e-4286-8801-6c02d7e72f4e" />
<img width="935" height="472" alt="TG6" src="https://github.com/user-attachments/assets/7c8bfe75-0ce6-46f9-a15e-b4e3aa669c99" />
<img width="967" height="572" alt="TG7" src="https://github.com/user-attachments/assets/583338b0-2457-4fae-9d06-0824c7b0cca2" />

### Batch Processing
<img width="914" height="524" alt="batch1" src="https://github.com/user-attachments/assets/1bb31f9f-4f00-4a6f-9a00-9f106beb3856" />
<img width="1061" height="522" alt="batch2" src="https://github.com/user-attachments/assets/e64b0ae7-a3ca-43d9-81a1-2800830fd3ac" />
<img width="1053" height="523" alt="batch3" src="https://github.com/user-attachments/assets/3a27971d-a7ce-462b-ac88-ae866b93d52d" />
<img width="960" height="341" alt="batch4" src="https://github.com/user-attachments/assets/19c1e2bd-4c8c-422d-8d84-2f3f397b2371" />
<img width="981" height="454" alt="batch5" src="https://github.com/user-attachments/assets/a8063039-293c-41d6-bae8-29a29d54a6ea" />
<img width="985" height="368" alt="batch6" src="https://github.com/user-attachments/assets/fa8bf123-00f8-4ad8-af13-23c496e9ab05" />

### Export Results
<img width="956" height="364" alt="finall" src="https://github.com/user-attachments/assets/c39cdbb3-90a2-433e-8f15-e2883f35a159" />
<img width="1366" height="659" alt="final2" src="https://github.com/user-attachments/assets/2779ce85-9d4a-443f-afb8-f9f65e3cf9a4" />
<img width="772" height="646" alt="final3" src="https://github.com/user-attachments/assets/290f4b61-38d5-44a3-b346-5b564adc499b" />
<img width="1037" height="593" alt="final4" src="https://github.com/user-attachments/assets/f238fbd5-5e9b-48ef-a3d6-80b48751042b" />


**X-10 ThreatFusion** - Command your intelligence, dominate the threat landscape.




