import numpy as np
from sklearn.neighbors import LocalOutlierFactor


class MLAnomalyDetector:
    """
    Optional session-level anomaly detection.
    Intended as supporting analysis, not primary evidence.
    """

    def __init__(self, sessions):
        self.sessions = sessions
        self.results = []

        # Interpretable, DFIR-aligned feature names
        self.feature_names = [
            "duration",
            "failed_logons",
            "successful_logons",
            "unique_tasks",
            "unique_services",
            "admin_added",
            "user_created",
            "logs_cleared",
            "total_events",
            "off_hours",
            "ip_present",
            "user_present"
        ]


    def _extract_features(self, session):
        """Extract session-level behavioral features (no time logic)."""

        events = session.get("events", [])

        # Session duration in seconds
        duration = 0
        if session.get("start_time") and session.get("end_time"):
            duration = (session["end_time"] - session["start_time"]).total_seconds()

        # Authentication-related activity
        failed = sum(1 for e in events if e["event_id"] == "4625")
        success = sum(1 for e in events if e["event_id"] in ("4624", "1149"))

        # Deduplicated persistence mechanisms
        unique_tasks = set()
        unique_services = set()

        for e in events:
            if e["event_id"] in ("4698", "129"):
                name = (
                    e["details"].get("TaskName")
                    or e["details"].get("Task")
                    or e["details"].get("Name")
                    or "UnknownTask"
                )
                unique_tasks.add(name)

            elif e["event_id"] == "7045":
                svc = (
                    e["details"].get("ServiceName")
                    or e["details"].get("Service")
                    or "UnknownService"
                )
                unique_services.add(svc)

        admin_add = sum(1 for e in events if e["event_id"] == "4732")
        user_create = sum(1 for e in events if e["event_id"] == "4720")
        logs_cleared = sum(1 for e in events if e["event_id"] == "1102")

        total_events = len(events)

        # Coarse temporal context (label only, not correlation)
        off_hours = 0
        if session.get("start_time"):
            hour = session["start_time"].hour
            if hour < 7 or hour > 21:
                off_hours = 1

        # Data completeness indicators
        ip_present = 1 if session.get("source_ip") else 0
        user_present = 1 if session.get("user") else 0

        return [
            duration,
            failed,
            success,
            len(unique_tasks),
            len(unique_services),
            admin_add,
            user_create,
            logs_cleared,
            total_events,
            off_hours,
            ip_present,
            user_present
        ]


    def run(self):
        """
        Run unsupervised anomaly detection across sessions.
        Skips execution when session count is too small.
        """

        # LOF is unreliable with very small samples
        if not self.sessions or len(self.sessions) < 5:
            print("[+] ML anomaly detection skipped (insufficient sessions)")
            return []

        X = []
        session_map = []

        for s in self.sessions:
            X.append(self._extract_features(s))
            session_map.append(s)

        X = np.array(X)

        lof = LocalOutlierFactor(
            n_neighbors=min(3, len(X) - 1),
            contamination="auto"
        )

        preds = lof.fit_predict(X)
        scores = lof.negative_outlier_factor_

        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0) + 1e-9

        for idx, (sess, pred, score, vec) in enumerate(zip(session_map, preds, scores, X)):
            if pred != -1:
                continue

            # Z-score explanation for interpretability
            z = (vec - means) / stds
            reasons = []

            for fname, zscore in zip(self.feature_names, z):
                if abs(zscore) < 1.5:
                    continue

                if fname == "duration":
                    reasons.append("Unusual session duration")
                elif fname == "unique_tasks":
                    reasons.append("Unusual scheduled task activity")
                elif fname == "unique_services":
                    reasons.append("Service installation behavior")
                elif fname == "admin_added":
                    reasons.append("Privilege escalation activity")
                elif fname == "user_created":
                    reasons.append("User account creation")
                elif fname == "logs_cleared":
                    reasons.append("Anti-forensics behavior")
                elif fname == "failed_logons":
                    reasons.append("Failed login anomaly")
                elif fname == "off_hours":
                    reasons.append("Off-hours access pattern")
                elif fname == "total_events":
                    reasons.append("High session activity volume")

            if not reasons:
                reasons.append("Statistically anomalous session behavior")

            self.results.append({
                "session_id": idx + 1,
                "user": sess.get("user"),
                "ip": sess.get("source_ip"),
                "start": sess.get("start_time"),
                "end": sess.get("end_time"),
                "severity": "High",
                "rule": "Statistical Session Anomaly (ML)",
                "description":
                    f"Session deviates from peer sessions based on statistical comparison "
                    f"(score={score:.4f})",
                "explanation": " | ".join(reasons)
            })

        print(f"[+] ML anomaly detection completed. Flagged {len(self.results)} sessions")
        return self.results
