# Red-DiscordBot Development Environment

Minimal setup for Red-DiscordBot development and custom cog creation.

## Setup

1. **Environment**: `python -m venv venv && source venv/bin/activate`
2. **Install**: `pip install -r requirements.txt`
3. **Setup**: `redbot-setup` (follow prompts - use "dev" as instance name)
4. **Run**: `redbot dev --token YOUR_BOT_TOKEN`

## Custom Cogs

- **Location**: `/workspace/cogs/`
- **Example**: See `cogs/example/` for basic structure
- **Load**: Use `[p]load example` in Discord (where `[p]` is bot prefix)

## Structure

```
/workspace/
├── venv/              # Virtual environment
├── cogs/              # Custom cogs directory
│   └── example/       # Example cog
└── requirements.txt   # Dependencies
```

## Commands

- `redbot dev --token YOUR_TOKEN` - Start bot
- `[p]load example` - Load example cog
- `[p]hello` - Test command from example cog