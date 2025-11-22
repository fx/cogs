# 🔴

Personal red development environment and cogs.

## Setup

1. **Environment**: `python -m venv venv && source venv/bin/activate`
2. **Install**: `pip install -r requirements.txt`
3. **Setup**: `redbot-setup` (follow prompts - use "dev" as instance name)
4. **Run**: `redbot dev --token YOUR_BOT_TOKEN`
5. **Add cogs path** (in Discord): `[p]addpath /workspace/cogs`

## Custom Cogs

| Cog                          | Description                                 |
| ---------------------------- | ------------------------------------------- |
| [forwarder](cogs/forwarder/) | Forward matching messages to HTTP endpoints |

## Structure

```
/workspace/
├── venv/              # Virtual environment
├── cogs/              # Custom cogs directory
│   └── forwarder/     # Message forwarding cog
└── requirements.txt   # Dependencies
```

## Commands

- `redbot dev --token YOUR_TOKEN` - Start bot
- `[p]load forwarder` - Load forwarder cog
- `[p]forward status` - Check forwarder configuration