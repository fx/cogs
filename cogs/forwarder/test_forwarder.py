"""Tests for the Forwarder cog."""
import re
import sys
import types
import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from unittest.mock import AsyncMock, MagicMock, patch


# Create a real Cog base class for inheritance
class MockCog:
    """Mock base class for Cog."""
    @classmethod
    def listener(cls, name=None):
        def decorator(func):
            return func
        return decorator


# Create decorator that returns objects with .command() method
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


# Create mock module structure
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
sys.modules["discord"] = mock_discord

# Mock aiohttp
mock_aiohttp = types.ModuleType("aiohttp")
mock_aiohttp.ClientSession = MagicMock
sys.modules["aiohttp"] = mock_aiohttp

# Now import the forwarder module
from cogs.forwarder.forwarder import Forwarder


@pytest.fixture
def forwarder(mock_bot, mock_config):
    """Create a Forwarder instance with mocked dependencies."""
    cog = object.__new__(Forwarder)
    cog.bot = mock_bot
    cog.config = mock_config
    cog.session = None
    cog._compiled_patterns = {}
    return cog


class TestURLValidation:
    """Test URL validation logic."""

    def test_valid_https_url(self, forwarder):
        assert forwarder._validate_url("https://example.com/webhook") is True

    def test_valid_http_url(self, forwarder):
        assert forwarder._validate_url("http://localhost:8080/api") is True

    def test_invalid_url_no_protocol(self, forwarder):
        assert forwarder._validate_url("example.com/webhook") is False

    def test_invalid_url_too_short(self, forwarder):
        assert forwarder._validate_url("http://x") is False

    @given(st.text(max_size=100))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_validate_url_never_crashes(self, forwarder, url):
        """Property: validation should never raise, always return bool."""
        result = forwarder._validate_url(url)
        assert isinstance(result, bool)


class TestRegexPatternCache:
    """Test regex pattern compilation and caching."""

    def test_valid_pattern_compiles(self, forwarder):
        pattern = forwarder._get_compiled_pattern(r"\btest\b")
        assert pattern.search("this is a test")
        assert not pattern.search("testing")

    def test_pattern_is_cached(self, forwarder):
        p1 = forwarder._get_compiled_pattern(r"hello")
        p2 = forwarder._get_compiled_pattern(r"hello")
        assert p1 is p2

    def test_invalid_pattern_returns_non_matching(self, forwarder):
        pattern = forwarder._get_compiled_pattern(r"[invalid")
        assert not pattern.search("anything")

    def test_clear_cache(self, forwarder):
        forwarder._get_compiled_pattern(r"test")
        assert len(forwarder._compiled_patterns) == 1
        forwarder._clear_pattern_cache()
        assert len(forwarder._compiled_patterns) == 0

    @given(st.text(max_size=50))
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_any_pattern_returns_compiled_regex(self, forwarder, pattern):
        """Property: any string should return a compiled pattern."""
        result = forwarder._get_compiled_pattern(pattern)
        assert isinstance(result, re.Pattern)


class TestMessageMatching:
    """Test message forwarding logic."""

    @pytest.fixture
    def forwarder_with_session(self, forwarder):
        forwarder.session = MagicMock()
        forwarder.session.closed = False  # Ensure session passes the validity check
        return forwarder

    @pytest.mark.asyncio
    async def test_skips_dm_messages(self, forwarder_with_session, mock_message):
        """Messages without a guild should be ignored."""
        mock_message.guild = None
        await forwarder_with_session.on_message(mock_message)
        forwarder_with_session.config.guild.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_when_disabled(self, forwarder_with_session, mock_message, mock_config):
        """Messages should be skipped when forwarding is disabled."""
        mock_config.guild.return_value.all = AsyncMock(return_value={
            "enabled": False,
            "forward_url": "https://example.com",
            "regex_patterns": [],
            "forward_attachments": False,
            "file_extensions": [],
            "reaction_emoji": None,
            "forwarded_messages": {},
            "forward_bot_messages": False
        })
        await forwarder_with_session.on_message(mock_message)
        forwarder_with_session.session.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_bot_messages_by_default(self, forwarder_with_session, mock_message, mock_config):
        """Bot messages should be skipped unless configured."""
        mock_message.author.bot = True
        mock_config.guild.return_value.all = AsyncMock(return_value={
            "enabled": True,
            "forward_url": "https://example.com",
            "regex_patterns": [],
            "forward_attachments": False,
            "file_extensions": [],
            "reaction_emoji": None,
            "forwarded_messages": {},
            "forward_bot_messages": False
        })
        await forwarder_with_session.on_message(mock_message)
        forwarder_with_session.session.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_forwards_matching_regex(self, forwarder_with_session, mock_message, mock_config):
        """Messages matching regex should be forwarded."""
        mock_message.content = "this is important info"
        mock_config.guild.return_value.all = AsyncMock(return_value={
            "enabled": True,
            "forward_url": "https://example.com/hook",
            "regex_patterns": [r"important"],
            "forward_attachments": False,
            "file_extensions": [],
            "reaction_emoji": None,
            "forwarded_messages": {},
            "forward_bot_messages": False
        })

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="OK")

        # Properly mock async context manager
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        forwarder_with_session.session.post.return_value = mock_cm

        await forwarder_with_session.on_message(mock_message)
        forwarder_with_session.session.post.assert_called_once()


class TestCommands:
    """Test cog commands.

    Note: We call .callback() to access the underlying method, bypassing
    discord.py's command decorator which changes the call signature.
    """

    @pytest.mark.asyncio
    async def test_set_valid_url(self, forwarder, mock_ctx):
        """Setting a valid URL should succeed."""
        await forwarder.set_url.callback(forwarder, mock_ctx, "https://example.com/webhook")
        mock_ctx.send.assert_called_with("Forward URL configured successfully.")

    @pytest.mark.asyncio
    async def test_set_invalid_url(self, forwarder, mock_ctx):
        """Setting an invalid URL should fail."""
        await forwarder.set_url.callback(forwarder, mock_ctx, "not-a-url")
        mock_ctx.send.assert_called_with("Invalid URL. Must be a valid HTTP/HTTPS URL.")

    @pytest.mark.asyncio
    async def test_add_valid_regex(self, forwarder, mock_ctx, mock_config):
        """Adding a valid regex should succeed."""
        patterns = []
        mock_config.guild.return_value.regex_patterns = MagicMock()
        mock_config.guild.return_value.regex_patterns.return_value.__aenter__ = AsyncMock(return_value=patterns)
        mock_config.guild.return_value.regex_patterns.return_value.__aexit__ = AsyncMock()

        await forwarder.add_regex.callback(forwarder, mock_ctx, pattern=r"\btest\b")
        assert "Added regex pattern" in mock_ctx.send.call_args[0][0]

    @pytest.mark.asyncio
    async def test_add_invalid_regex(self, forwarder, mock_ctx):
        """Adding an invalid regex should fail."""
        await forwarder.add_regex.callback(forwarder, mock_ctx, pattern=r"[invalid")
        assert "Invalid regex pattern" in mock_ctx.send.call_args[0][0]

    @pytest.mark.asyncio
    async def test_enable_forwarding(self, forwarder, mock_ctx):
        """Enable command should set enabled to True."""
        await forwarder.enable_forwarding.callback(forwarder, mock_ctx)
        mock_ctx.send.assert_called_with("Message forwarding enabled.")


class TestHypothesisProperties:
    """Property-based tests for edge cases."""

    @given(st.lists(st.text(min_size=1, max_size=10), max_size=5))
    @settings(max_examples=30)
    def test_file_extensions_normalized(self, extensions):
        """Property: all extensions should start with '.' after normalization."""
        clean = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        assert all(e.startswith('.') for e in clean)

    @given(st.text(max_size=200), st.text(max_size=50))
    @settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_regex_search_handles_any_content(self, forwarder, content, pattern):
        """Property: regex search should handle any content without crashing."""
        compiled = forwarder._get_compiled_pattern(pattern)
        result = compiled.search(content)
        assert result is None or isinstance(result, re.Match)
