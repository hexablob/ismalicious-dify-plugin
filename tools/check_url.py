from collections.abc import Generator
from typing import Any
from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from gate_client import GateClient, denied


class CheckUrlTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage]:
        try:
            result = GateClient(self.runtime.credentials).check_url(tool_parameters.get("url"))
        except ValueError:
            result = denied("Both API credentials are required; processing refused.")
        yield self.create_variable_message("allowed", result["allowed"])
        yield self.create_variable_message("result", result)
        yield self.create_json_message(result)
