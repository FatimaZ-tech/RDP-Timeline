# RDPTimeline

**RDPTimeline** is a Digital Forensics & Incident Response (DFIR) tool that reconstructs RDP sessions from Windows Event Logs using timeline analysis, then correlates and flags suspicious activity occurring within and around those sessions using deterministic forensic rules, with optional ML and AI-based explanation.

The tool is designed to work **offline by default**.

---

## What RDPTimeline Does

RDPTimeline follows a staged DFIR pipeline:

1. Log ingestion and validation  
2. Event parsing and normalization  
3. Global timeline based RDP session reconstruction  
4. Temporal correlation using grace windows  
5. Rule-based DFIR analysis  
6. *(Optional)* ML-based session anomaly detection  
7. *(Optional)* AI-assisted forensic reporting  

---

## Forensic Indicators Highlighted

RDPTimeline applies deterministic DFIR rules to reconstructed RDP sessions to highlight **forensic indicators commonly associated with suspicious activity**.

The tool may surface indicators related to:

### Authentication Abuse
- Repeated failed RDP authentication attempts
- Short-lived or aborted RDP sessions

### Session Anomalies
- Unusually short or long RDP sessions
- Sessions without a clean logoff or disconnect

### Account & Privilege Activity
- Local user account creation during or near RDP sessions
- Users added to privileged (administrator) groups

### Persistence Mechanisms
- Scheduled task creation (with filtering of common benign tasks)
- Service installation and associated binary paths

### Anti-Forensics
- Clearing of Windows Security Event Logs

### Statistical Session Outliers *(Optional)*
- Sessions that significantly deviate from peer behavior based on duration, activity volume, authentication patterns, or timing

> These indicators are **contextual signals** intended to support forensic
> investigation. They do not constitute proof of compromise on their own.

---

## Supported Windows Event Logs

You must provide **at least one** EVTX file.

Supported logs:
- `Security.evtx`
- `TerminalServices-RemoteConnectionManager.evtx`
- `LocalSessionManager.evtx`
- `System.evtx`
- `TaskScheduler.evtx`

> Logs may be provided in **any combination**.  
> Missing logs are handled gracefully.

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/FatimaZ-tech/RDPTimeline.git
cd RDPTimeline
pip install -r requirements.txt
```
---

## How to Run RDPTimeline

RDPTimeline is executed **from inside the project directory**.  
You must explicitly provide **full or relative paths** to the EVTX log files.

### Basic DFIR Analysis (Offline)

```bash
python rdptimeline.py \
  --security /path/to/Security.evtx \
  --ts /path/to/TerminalServices-RemoteConnectionManager.evtx \
  --lsm /path/to/LocalSessionManager.evtx
```

### Include System Persistence and Task Activity

```bash
python rdptimeline.py \
  --security /path/to/Security.evtx \
  --ts /path/to/TerminalServices-RemoteConnectionManager.evtx \
  --lsm /path/to/LocalSessionManager.evtx \
  --system /path/to/System.evtx \
  --tasks /path/to/TaskScheduler.evtx
```

### Enable ML-Based Anomaly Detection (Optional)

```bash
python rdptimeline.py \
  --security /path/to/Security.evtx \
  --ts /path/to/TerminalServices-RemoteConnectionManager.evtx \
  --lsm /path/to/LocalSessionManager.evtx \
  --system /path/to/System.evtx \
  --tasks /path/to/TaskScheduler.evtx
  --enable-ml
```
ML results are supporting signals only and do not replace rule-based DFIR findings.

### Enable AI-Assisted Forensic Explanations (Optional)

```bash
python rdptimeline.py \
  --security /path/to/Security.evtx \
  --ts /path/to/TerminalServices-RemoteConnectionManager.evtx \
  --lsm /path/to/LocalSessionManager.evtx \
  --system /path/to/System.evtx \
  --tasks /path/to/TaskScheduler.evtx
  --enable-ai-report
```
Must enter OpenAI key.
AI output is non-authoritative and used only for explanation.
Rule-based DFIR findings remain the source of truth.

---

## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this software for research, educational, and operational purposes, provided that the original copyright notice and license are included.

See the `LICENSE` file for full license text.

---

## Author

Developed by **Fatima Zakir** as part of ongoing research in Digital Forensics & Incident Response (DFIR).
