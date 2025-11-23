"""Root conftest for pytest.

This file sets up mock modules before any package imports occur,
enabling testing of Red-DiscordBot cogs without the actual redbot package.
"""
import sys
import types
from unittest.mock import MagicMock


# Create mock module structure for redbot BEFORE any imports
class MockCog:
    """Mock base class for Cog."""
    @classmethod
    def listener(cls, name=None):
        def decorator(func):
            return func
        return decorator


class MockGroup:
    """Mock for command groups."""
    def __init__(self, func):
        self.func = func
        self.callback = func

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)

    def command(self, **kwargs):
        def decorator(func):
            func.callback = func
            return func
        return decorator


def mock_group(**kwargs):
    def decorator(func):
        return MockGroup(func)
    return decorator


# Create mock modules
mock_commands = types.ModuleType("commands")
mock_commands.Cog = MockCog
mock_commands.group = mock_group
mock_commands.guild_only = lambda: lambda f: f

mock_checks = types.ModuleType("checks")
mock_checks.admin = lambda: lambda f: f

mock_config = MagicMock()

mock_bot_module = types.ModuleType("bot")
mock_bot_module.Red = MagicMock

mock_chat_formatting = types.ModuleType("chat_formatting")
mock_chat_formatting.box = lambda x: f"```{x}```"

mock_utils = types.ModuleType("utils")
mock_utils.chat_formatting = mock_chat_formatting

mock_redbot_core = types.ModuleType("core")
mock_redbot_core.commands = mock_commands
mock_redbot_core.Config = mock_config
mock_redbot_core.checks = mock_checks
mock_redbot_core.bot = mock_bot_module
mock_redbot_core.utils = mock_utils

mock_redbot = types.ModuleType("redbot")
mock_redbot.core = mock_redbot_core

# Register mock modules
sys.modules["redbot"] = mock_redbot
sys.modules["redbot.core"] = mock_redbot_core
sys.modules["redbot.core.commands"] = mock_commands
sys.modules["redbot.core.bot"] = mock_bot_module
sys.modules["redbot.core.utils"] = mock_utils
sys.modules["redbot.core.utils.chat_formatting"] = mock_chat_formatting

# Mock discord
mock_discord = types.ModuleType("discord")
mock_discord.Message = MagicMock
mock_discord.Reaction = MagicMock
mock_discord.User = MagicMock
mock_discord.RawReactionActionEvent = MagicMock
mock_discord.Forbidden = Exception
mock_discord.HTTPException = Exception
mock_discord.NotFound = Exception
sys.modules["discord"] = mock_discord

# Mock aiohttp
mock_aiohttp = types.ModuleType("aiohttp")
mock_aiohttp.ClientSession = MagicMock
sys.modules["aiohttp"] = mock_aiohttp
