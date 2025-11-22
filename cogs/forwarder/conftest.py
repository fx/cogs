"""Shared fixtures for Red-DiscordBot cog testing."""
import pytest
from unittest.mock import AsyncMock, MagicMock, PropertyMock


@pytest.fixture
def mock_bot():
    """Mock Red bot instance."""
    bot = MagicMock()
    bot.user = MagicMock(id=123456789, name="TestBot")
    bot.wait_until_ready = AsyncMock()
    return bot


@pytest.fixture
def mock_guild():
    """Mock Discord guild."""
    guild = MagicMock()
    guild.id = 111111111
    guild.name = "Test Guild"
    return guild


@pytest.fixture
def mock_channel(mock_guild):
    """Mock Discord text channel."""
    channel = MagicMock()
    channel.id = 222222222
    channel.name = "test-channel"
    channel.guild = mock_guild
    return channel


@pytest.fixture
def mock_author():
    """Mock Discord user/member."""
    author = MagicMock()
    author.id = 333333333
    author.name = "testuser"
    author.display_name = "Test User"
    author.bot = False
    author.avatar = MagicMock()
    author.avatar.url = "https://cdn.discordapp.com/avatars/123/abc.png"
    return author


@pytest.fixture
def mock_message(mock_channel, mock_author, mock_guild):
    """Mock Discord message."""
    message = MagicMock()
    message.id = 444444444
    message.content = "test message content"
    message.channel = mock_channel
    message.author = mock_author
    message.guild = mock_guild
    message.attachments = []
    message.embeds = []
    message.jump_url = "https://discord.com/channels/111/222/444"
    message.created_at = MagicMock()
    message.created_at.isoformat.return_value = "2024-01-01T00:00:00"
    return message


@pytest.fixture
def mock_ctx(mock_bot, mock_guild, mock_channel, mock_author):
    """Mock command context."""
    ctx = AsyncMock()
    ctx.bot = mock_bot
    ctx.guild = mock_guild
    ctx.channel = mock_channel
    ctx.author = mock_author
    ctx.send = AsyncMock()
    return ctx


@pytest.fixture
def mock_config():
    """Mock Red Config with default guild settings."""
    config = MagicMock()

    # Default guild config values
    default_data = {
        "forward_url": None,
        "regex_patterns": [],
        "forward_attachments": True,
        "file_extensions": [],
        "enabled": False,
        "reaction_emoji": None,
        "forwarded_messages": {},
        "forward_bot_messages": False
    }

    guild_config = MagicMock()
    guild_config.all = AsyncMock(return_value=default_data.copy())
    guild_config.forward_url = AsyncMock(return_value=None)
    guild_config.forward_url.set = AsyncMock()
    guild_config.regex_patterns = AsyncMock(return_value=[])
    guild_config.enabled = AsyncMock(return_value=False)
    guild_config.enabled.set = AsyncMock()

    config.guild = MagicMock(return_value=guild_config)
    config.register_guild = MagicMock()

    return config
