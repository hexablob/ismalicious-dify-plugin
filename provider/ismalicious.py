from typing import Any
from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError
from gate_client import GateClient

class IsmaliciousProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            result = GateClient(credentials).check_url("https://example.com")
        except ValueError:
            raise ToolProviderCredentialValidationError("Both IsMalicious credentials are required.") from None
        if result["error"]:
            raise ToolProviderCredentialValidationError("Credentials or Gate access could not be verified.")
