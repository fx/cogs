# 🔴

Personal red development environment and cogs.

## Installation

```
[p]repo add fx-cogs https://github.com/fx/cogs
[p]cog install fx-cogs <cog-name>
[p]load <cog-name>
```

## Cogs

| Cog                      | Description                                 |
| ------------------------ | ------------------------------------------- |
| [forwarder](forwarder/)  | Forward matching messages to HTTP endpoints |

## Structure

```
/workspace/
├── .data/             # Red instance data (gitignored)
├── venv/              # Virtual environment (gitignored)
├── forwarder/         # Message forwarding cog
├── example/           # Example cog for development
├── info.json          # Repository metadata for Downloader
└── requirements.txt   # Dependencies
```

## Development

1. **Environment**: `python -m venv venv && source venv/bin/activate`
2. **Install**: `pip install -r requirements.txt`
3. **Setup**: `redbot-setup --no-prompt --instance-name dev --data-path ./.data --backend json`
4. **Run**: `redbot dev --token YOUR_BOT_TOKEN`
5. **Add cogs path** (in Discord): `[p]addpath /path/to/repo`
6. **Load cog**: `[p]load forwarder`