# IsMalicious for Dify

Check untrusted text for prompt injection and link reputation before a selected workflow step. The plugin provides `scan_content` and `check_url` as API-backed Tools. It is not a universal agent middleware or an MCP stdio bridge.

Source: https://github.com/hexablob/ismalicious-dify-plugin

Contact: contact@ismalicious.com

## Setup

1. Create an [IsMalicious account](https://ismalicious.com/app/account) and obtain a matching API key and secret.
2. Install the package and enter both credentials in the provider's secret fields. Credential validation calls `check_url` on `https://example.com` and consumes one scan.
3. Configure a `scan_content` Tool node with exact text and optional original `source_url`.
4. Add an If-Else node testing Boolean output `allowed` **is true**. Only its true branch may reach the selected LLM. Its false branch must end or route to operator review.
5. Keep tool errors configured to terminate. Do not connect the unchecked original text to a second LLM path that bypasses the If-Else node.

Both tools return `allowed` and `result` output variables plus a JSON message. `result.result` preserves the complete API response, unknown link reputations, future fields and `links_truncated`.

## Decisions

- `allow` with a complete link scan produces `allowed=true`. It means no blocking under current API rules, not proof of benign content or known-good URL reputation.
- `warn`, `block`, truncated links, malformed responses, HTTP failures and timeouts produce `allowed=false`.
- No retries occur on HTTP 429. Rejected text is not emitted as replacement instructions for the LLM.
- The URL tool checks reputation at a fixed API origin and never fetches the destination.
- Exact text is serialized as UTF-8 JSON. Bodies over 1 MiB are refused without truncation or an API call.

## Network and quotas

The plugin is free to install and contains no purchase or subscription checkout. It uses the external IsMalicious service, which requires an account and a matching API key and secret. API access has scan quotas and may require a paid subscription depending on your plan. Check your account plan before using the plugin.

Only `https://api.ismalicious.com/gate/scan` and `/gate/url` are contacted. TLS verification is enabled, redirects disabled, timeout 15 seconds. Gate requests consume your separate scan quota.

Submitted text and URLs can contain personal data or identifying indicators depending on what you select. They are transmitted to IsMalicious for prompt-injection and link-reputation analysis. The plugin does not automatically remove personal data. Remove passwords, authentication tokens and sensitive personal information before scanning. Read [PRIVACY.md](PRIVACY.md), the [IsMalicious privacy policy](https://ismalicious.com/privacy) and [account terms](https://ismalicious.com/terms) before sending organizational data. The plugin requires Python 3.12 and Dify's plugin runtime.

## Verification and limitations

Tests invoke the released Dify Plugin SDK 0.10.2 with mocked HTTP transport, verify native output-variable messages and the explicit Boolean recipe condition, and cover refusals, malformed JSON, timeouts, quota failures and URL preservation. Synthetic fixtures demonstrate integration behavior, not detector accuracy.

Installation and graph execution in Dify Community Edition or Dify Cloud have not yet been verified. The recipe is written instructions, not a tested importable workflow. Marketplace publication remains pending the owner's explicit approval of the [Marketplace Agreement](https://dify.ai/legal/marketplace-agreement). SDK tests are not CE or Cloud certification.

## Development

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q tests
```

Use the official Dify CLI to package a runtime-only staging directory, excluding tests, Git metadata, environments and caches.

AI assistance was used to prepare this integration and its tests.
