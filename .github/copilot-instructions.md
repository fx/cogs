# GitHub Copilot Instructions

## Repository Information

- Repository owner: fx
- Use "fx" for author attribution in info.json and similar metadata files

## Code Reviews

### Substantive Reviews Only
- Focus reviews on actual code quality, security, correctness, and functionality issues
- Do not flag emojis in code, logs, comments, or documentation as issues
- Do not suggest style changes for language, wording preferences, or formatting that does not affect functionality
- Ignore purely cosmetic or stylistic preferences (nitpicks)

### Forwarder Cog Specifics
- The forwarder cog is designed for general-purpose HTTP/HTTPS URL forwarding, not specifically Discord webhooks
- Do not suggest Discord webhook-specific terminology or validation
- Use "Forward URL" instead of "Webhook URL" in messages
- Use "Message forwarding" instead of "Webhook forwarding" in status messages
- Accept any valid HTTP/HTTPS URL as a forwarding target