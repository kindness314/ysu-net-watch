from dataclasses import dataclass


@dataclass
class RecoveryState:
    """One recovery episode; no credentials or portal session data are stored."""

    failures: int = 0
    device_release_attempted: bool = False
    workflow_session_retry_attempted: bool = False

    def reset(self) -> None:
        self.failures = 0
        self.device_release_attempted = False
        self.workflow_session_retry_attempted = False

    def claim_device_release(self) -> bool:
        # Claim BEFORE the destructive request: a timeout may hide a successful kick.
        if self.device_release_attempted:
            return False
        self.device_release_attempted = True
        return True

    def claim_workflow_session_retry(self) -> bool:
        """Allow one fresh portal session after CAS reached a stale workflow."""
        if self.workflow_session_retry_attempted:
            return False
        self.workflow_session_retry_attempted = True
        return True
