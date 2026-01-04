import os


class LogLoader:
    def __init__(self, security=None, ts=None, lsm=None, system=None, tasks=None):
        """
        Accepts paths to different Windows EVTX logs.
        Each argument is optional, but at least one must be provided.
        """
        self.security = security      # Security.evtx
        self.ts = ts                  # TerminalServices-RemoteConnectionManager.evtx
        self.lsm = lsm                # LocalSessionManager.evtx
        self.system = system          # System.evtx
        self.tasks = tasks            # TaskScheduler.evtx


    def validate_file(self, path, name):
        """
        Validate that an EVTX file exists and has the correct extension.
        Returns None if the log was not supplied.
        """

        # Allow missing logs (not all investigations have every log)
        if path is None:
            return None
        
        # Ensure the file actually exists on disk
        if not os.path.exists(path):
            raise FileNotFoundError(f"[ERROR] {name} log not found at: {path}")
        
        # Basic sanity check to ensure EVTX format
        if not path.lower().endswith(".evtx"):
            raise ValueError(f"[ERROR] {name} must be an .evtx file")
        
        # Informational message for the user / CLI
        print(f"[OK] {name} log found → {path}")

        return path


    def load_logs(self):
        """
        Validate all provided logs.
        Ensures at least one EVTX file is supplied.
        """

        # Validate each log independently
        security = self.validate_file(self.security, "Security")
        ts = self.validate_file(self.ts, "Terminal Services (RemoteConnectionManager)")
        lsm = self.validate_file(self.lsm, "Local Session Manager")
        system = self.validate_file(self.system, "System")
        tasks = self.validate_file(self.tasks, "Task Scheduler")

        # Prevent running the pipeline with zero evidence
        if (
            security is None
            and ts is None
            and lsm is None
            and system is None
            and tasks is None
        ):
            raise ValueError("No logs provided. At least one EVTX file is required.")

        # Return validated paths for downstream parsing
        return {
            "security": security,
            "ts": ts,
            "lsm": lsm,
            "system": system,
            "tasks": tasks
        }
