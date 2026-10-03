# Plugin privacy

This plugin sends selected text, optional source URL, or a selected URL to the IsMalicious Gate API at `api.ismalicious.com`. Credentials are transmitted to that API as a Base64-encoded key/secret pair in `X-API-KEY` over verified HTTPS. Base64 is an encoding, not encryption.

The plugin itself does not persist submitted content, credentials or responses, and contains no analytics or request-body logging. It returns evidence to Dify; Dify may store inputs, outputs or traces under the operator's settings. The hosted IsMalicious service has its own account terms and data-processing practices. This plugin does not claim a service retention period.

The operator must approve external transmission and avoid passwords, authentication tokens and sensitive personal information. Do not use this plugin for health, financial, biometric, children's or other highly sensitive data without an appropriate agreement and assessment.

The plugin does not fetch the URL being checked, execute submitted text, access the filesystem or forward credentials to user-provided hosts. Its manifest grants no persistent-storage, LLM, app or endpoint permission.

Privacy questions or deletion requests: contact@ismalicious.com.
