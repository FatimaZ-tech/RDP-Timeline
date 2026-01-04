from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import datetime

# XML namespace used by Windows Event Logs
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# RDP + DFIR relevant event IDs only
# Parser extracts evidence, not detections
RDP_RELEVANT_EVENTS = {
    "4624": "Successful Logon",        # RDP when LogonType = 10
    "4625": "Failed Logon",
    "4634": "Logoff",

    "1149": "RDP Authentication Successful",
    "21": "RDP Session Connect",
    "22": "Shell Start",
    "24": "Session Disconnect",

    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4723": "Password Change Attempt",
    "4724": "Password Reset Attempt",
    "4725": "User Account Disabled",

    "4732": "User Added To Privileged Group",
    "4728": "User Added To Security Group",

    "7045": "New Service Installed",
    "4698": "Scheduled Task Created",

    "1102": "Security Logs Cleared",
    "129": "Scheduled Task Registered (TaskScheduler)"
}


class RDPEventParser:

    def __init__(self):
        self.events = []  # Collected parsed events


    def _convert_time(self, ts):
        """Convert ISO timestamp string to datetime object."""
        if not ts or ts == "N/A":
            return None

        try:
            # Converts e.g. 2026-01-01T00:11:56.007219Z
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            # Invalid or malformed timestamps are ignored
            return None


    def parse_evtx(self, path, source_name):
        """Parse an EVTX file and extract relevant DFIR events."""
        print(f"[+] Parsing {source_name}: {path}")

        count = 0

        with Evtx(path) as log:
            for record in log.records():

                # Parse XML record
                try:
                    root = ET.fromstring(record.xml())
                except:
                    # Skip malformed XML records
                    continue

                system = root.find(f"{NS}System")
                if system is None:
                    continue

                # Extract Event ID
                eid_node = system.find(f"{NS}EventID")
                if eid_node is None:
                    continue

                event_id = eid_node.text.strip()

                # Ignore irrelevant events early
                if event_id not in RDP_RELEVANT_EVENTS:
                    continue

                # Extract timestamp from SystemTime attribute
                time_node = system.find(f"{NS}TimeCreated")
                timestamp = (
                    time_node.attrib.get("SystemTime")
                    if time_node is not None else "N/A"
                )

                # Core event structure
                event = {
                    "event_id": event_id,
                    "event_name": RDP_RELEVANT_EVENTS[event_id],
                    "timestamp": timestamp,                    # raw evidence
                    "parsed_time": self._convert_time(timestamp),  # analysis-friendly
                    "source": source_name,
                    "details": {}
                }

                # Extract EventData fields (Security / System / RDP logs)
                event_data = root.find(f"{NS}EventData")
                if event_data is not None:
                    for d in event_data:
                        name = d.attrib.get("Name", "")
                        event["details"][name] = d.text

                # Extract UserData fields (TaskScheduler and others)
                user_data = root.find(f"{NS}UserData")
                if user_data is not None:
                    for elem in user_data.iter():
                        if elem.text and elem.tag:
                            clean_name = elem.tag.replace(NS, "")
                            event["details"][clean_name] = elem.text

                self.events.append(event)
                count += 1

        print(f"[OK] Extracted {count} relevant events from {source_name}")


    def get_events(self):
        """Return all parsed events."""
        return self.events
