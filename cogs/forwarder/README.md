# Forwarder

Forward Discord messages to any HTTP endpoint based on regex patterns or attachments.

I primarily use this to forward certain attachments to a n8n webhook trigger URL, trigger webhooks when a message includes keywords, or use a reaction emoji to manually trigger the forward.

Currently this only supports one URL per server (guild), so you need something like a n8n workflow to fan out to other workflows based on the message received.

## Installation

```
[p]load forwarder
```

## Commands

All commands require admin permissions and use the `[p]forward` prefix.

| Command                 | Description                                   |
| ----------------------- | --------------------------------------------- |
| `url <url>`             | Set the destination URL                       |
| `addregex <pattern>`    | Add a regex pattern to match                  |
| `removeregex <pattern>` | Remove a regex pattern                        |
| `listregex`             | List configured patterns                      |
| `attachments [on/off]`  | Toggle attachment forwarding                  |
| `fileext [.ext ...]`    | Filter by file extensions (e.g., `.mp3 .wav`) |
| `reaction [emoji]`      | Set emoji for manual forwarding               |
| `botmessages [on/off]`  | Toggle forwarding bot messages                |
| `enable` / `disable`    | Toggle forwarding                             |
| `status`                | Show current configuration                    |

## Quick Start

```
[p]forward url https://your-endpoint.com/webhook
[p]forward addregex (?i)important
[p]forward enable
```

## Payload Format

Messages are sent as JSON POST requests:

```json
{
  "forwarded_at": "2024-01-01T00:00:00",
  "is_reaction_forward": false,
  "message": {
    "message_id": "123",
    "channel_name": "general",
    "author": {"username": "user", "display_name": "User"},
    "content": "message text",
    "attachments": [{"filename": "file.mp3", "url": "..."}],
    "jump_url": "https://discord.com/..."
  }
}
```
