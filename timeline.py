import datetime

# Temporal correlation windows to account for async Windows logging
GRACE_BEFORE = datetime.timedelta(minutes=5)
GRACE_AFTER  = datetime.timedelta(minutes=15)

# Used only when no explicit disconnect/logoff is observed
INACTIVITY_TIMEOUT = datetime.timedelta(minutes=60)


class RDPTimelineBuilder:

    def __init__(self, events):
        self.raw_events = events
        self.timeline = []
        self.sessions = []


    def _parse_timestamp(self, ts):
        """Fallback parser for malformed or missing timestamps."""
        try:
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            return None


    def build_timeline(self):
        """Build a global UTC-sorted event timeline."""

        # Ensure all events have a parsed datetime for sorting
        for ev in self.raw_events:
            if not ev.get("parsed_time"):
                ev["parsed_time"] = self._parse_timestamp(ev.get("timestamp"))

        # Sort events chronologically using UTC time
        self.timeline = sorted(
            self.raw_events,
            key=lambda x: x.get("parsed_time") or datetime.datetime.min
        )

        print(f"[+] Timeline built with {len(self.timeline)} events")
        return self.timeline


    def build_sessions(self):
        """Reconstruct RDP sessions using DFIR-correct semantics."""

        current_session = None
        last_event_time = None

        for ev in self.timeline:
            eid = ev.get("event_id")
            t = ev.get("parsed_time")
            details = ev.get("details", {})

            if not t:
                continue

            # Best-effort user extraction across log sources
            user = (
                details.get("TargetUserName")
                or details.get("SubjectUserName")
                or details.get("User")
                or details.get("AccountName")
                or details.get("Param1")
            )

            # Best-effort source IP extraction across log sources
            ip = (
                details.get("IpAddress")
                or details.get("ClientAddress")
                or details.get("SourceNetworkAddress")
                or details.get("Address")
                or details.get("Param3")
            )

            # Close session if long inactivity suggests "silent" termination
            if current_session and last_event_time:
                if t - last_event_time > INACTIVITY_TIMEOUT:
                    current_session["end_time"] = last_event_time
                    current_session["end_reason"] = "inactivity_timeout"
                    self.sessions.append(current_session)
                    current_session = None

            last_event_time = t

            # Event 21 is the only authoritative RDP session start
            if eid == "21":
                if current_session:
                    current_session["end_time"] = t
                    current_session["end_reason"] = "overlapping_session_start"
                    self.sessions.append(current_session)

                ev["_correlation"] = "in_session"

                current_session = {
                    "start_time": t,
                    "end_time": None,
                    "start_reason": "lsm_session_start",
                    "end_reason": None,
                    "user": user,
                    "source_ip": ip,
                    "events": [ev]
                }
                continue

            # Attach events occurring within an active session
            if current_session:
                ev["_correlation"] = "in_session"
                current_session["events"].append(ev)

                # Explicit disconnect or logoff ends the session
                if eid in ("24", "4634"):
                    current_session["end_time"] = t
                    current_session["end_reason"] = "explicit_logoff"
                    self.sessions.append(current_session)
                    current_session = None

        # Close any session left open at end of logs
        if current_session:
            current_session["end_time"] = last_event_time
            current_session["end_reason"] = "session_open_at_log_end"
            self.sessions.append(current_session)

        print(f"[+] Built {len(self.sessions)} RDP sessions")

        # DFIR events correlated temporally to sessions using grace windows
        dfir_ids = {
            "4720", "4722", "4724", "4728", "4732",
            "4698", "7045", "1102"
        }

        dfir_events = [e for e in self.timeline if e.get("event_id") in dfir_ids]

        for ev in dfir_events:
            t = ev.get("parsed_time")
            if not t:
                continue

            for s in self.sessions:
                start = s["start_time"] - GRACE_BEFORE
                end = (s["end_time"] or s["start_time"]) + GRACE_AFTER

                if start <= t <= end:
                    # Explicitly label grace-based correlation
                    if t < s["start_time"]:
                        ev["_correlation"] = "grace_before"
                    else:
                        ev["_correlation"] = "grace_after"

                    s["events"].append(ev)
                    break

        return self.sessions


    def get_sessions(self):
        """Return fully reconstructed RDP sessions with DFIR correlations."""
        return self.sessions
