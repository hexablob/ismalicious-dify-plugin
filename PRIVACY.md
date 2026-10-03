# Plugin privacy

This plugin sends selected text, optional source URL, or a selected URL to the IsMalicious Gate API at `api.ismalicious.com`. Credentials are transmitted to that API as a Base64-encoded key/secret pair in `X-API-KEY` over verified HTTPS. Base64 is an encoding, not encryption.

Selected text and URLs may contain personal data depending on the operator's input, including names, email addresses or indicators that identify individuals. Those inputs are transmitted to IsMalicious for prompt-injection and link-reputation analysis. The plugin does not automatically strip or anonymize personal data. The transmitted data types are selected content, optional source URL or checked URL, and the account API key/secret used to authenticate the request.

The plugin itself does not persist submitted content, credentials or responses, and contains no analytics or request-body logging. It returns evidence to Dify; Dify may store inputs, outputs or traces under the operator's settings. The hosted IsMalicious service has its own [privacy policy](https://ismalicious.com/privacy) and [account terms](https://ismalicious.com/terms). This plugin does not claim a service retention period.

The operator must approve external transmission and ensure permission to submit any personal data. Do not submit passwords, authentication tokens, health, financial, biometric, children's or other highly sensitive data. Dify Cloud also restricts sensitive personal data under its [Terms of Service](https://dify.ai/legal/terms-of-service). Review any applicable data-processing arrangement before sending organizational data.

The plugin does not fetch the URL being checked, execute submitted text, access the filesystem or forward credentials to user-provided hosts. Its manifest grants no persistent-storage, LLM, app or endpoint permission.

Privacy questions or deletion requests: contact@ismalicious.com.
