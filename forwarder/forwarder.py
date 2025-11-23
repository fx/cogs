import re
import logging
import asyncio
import aiohttp
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

import discord
from redbot.core import commands, Config, checks
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import box

log = logging.getLogger("red.forwarder")

class Forwarder(commands.Cog):
    """Forward messages to any URL based on regex patterns and attachments"""
    
    def __init__(self, bot: Red):
        self.bot = bot
        # Unique identifier generated for the forwarder cog to avoid config conflicts
        self.config = Config.get_conf(self, identifier=823456789012345678)
        default_guild = {
            "forward_url": None,
            "regex_patterns": [],
            "forward_attachments": True,
            "file_extensions": [],
            "enabled": False,
            "reaction_emoji": "🔁",
            "forwarded_messages": {},
            "forward_bot_messages": False,
            "skip_own_commands": True
        }
        self.config.register_guild(**default_guild)
        self.session = None
        self._compiled_patterns = {}  # Cache for compiled regex patterns
        self._forwarding_locks = set()  # Prevent race conditions in reaction forwarding
        self._confirmation_emojis = ["▶️", "⏩", "⏭️"]  # Cycling emojis for forward confirmation
        self._warning_emoji = "⚠️"  # Emoji to indicate forward failure
    
    async def cog_load(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession()
    
    async def cog_unload(self):
        """Cleanup aiohttp session"""
        if self.session:
            await self.session.close()
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format using proper URL parsing."""
        try:
            parsed = urlparse(url)
            # Must have http/https scheme and a valid netloc (domain)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False
    
    def _get_compiled_pattern(self, pattern: str) -> re.Pattern:
        """Get or compile and cache a regex pattern"""
        if pattern not in self._compiled_patterns:
            try:
                self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                # If the pattern is invalid, cache a regex that never matches.
                # This ensures repeated checks for the same invalid pattern are
                # efficient and safe, avoiding re-compilation attempts.
                log.debug(f"Invalid regex pattern '{pattern}' - caching never-matching pattern")
                self._compiled_patterns[pattern] = re.compile("(?!.*)")
        return self._compiled_patterns[pattern]
    
    def _clear_pattern_cache(self):
        """Clear the compiled pattern cache"""
        self._compiled_patterns.clear()

    async def _is_own_command(self, message: discord.Message) -> bool:
        """Check if a message is a command directed at this bot.

        Returns True if the message starts with one of the bot's configured prefixes.
        """
        if not message.content:
            return False

        try:
            prefixes = await self.bot._prefix_cache.get_prefixes(message.guild)
            return any(message.content.startswith(prefix) for prefix in prefixes)
        except Exception as e:
            log.warning(f"Error checking command prefixes: {e}")
            return False

    async def _cleanup_old_forwarded_messages(self, guild, max_age_hours: int = 24, max_entries: int = 1000):
        """Remove old entries from forwarded_messages to prevent unbounded growth.

        Args:
            guild: The Discord guild to clean up
            max_age_hours: Remove entries older than this many hours (default: 24)
            max_entries: Maximum number of entries to keep (default: 1000)
        """
        async with self.config.guild(guild).forwarded_messages() as forwarded:
            if not forwarded:
                return

            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

            # Remove old entries
            expired_keys = []
            for msg_id, data in forwarded.items():
                try:
                    forwarded_at = datetime.fromisoformat(data.get("forwarded_at", ""))
                    if forwarded_at < cutoff_time:
                        expired_keys.append(msg_id)
                except (ValueError, TypeError):
                    # Invalid timestamp, mark for removal
                    expired_keys.append(msg_id)

            for key in expired_keys:
                del forwarded[key]

            # If still over limit, remove oldest entries
            if len(forwarded) > max_entries:
                sorted_entries = sorted(
                    forwarded.items(),
                    key=lambda x: x[1].get("forwarded_at", ""),
                    reverse=True
                )
                # Keep only the newest max_entries
                keys_to_keep = {k for k, _ in sorted_entries[:max_entries]}
                keys_to_remove = [k for k in forwarded if k not in keys_to_keep]
                for key in keys_to_remove:
                    del forwarded[key]

            if expired_keys or len(forwarded) > max_entries:
                log.debug(f"Cleaned up forwarded_messages: removed {len(expired_keys)} expired entries")

    @commands.group(name="forward")
    @checks.admin()
    async def urlforward(self, ctx):
        """Message forwarding configuration"""
        pass
    
    @urlforward.command(name="url")
    @commands.guild_only()
    async def set_url(self, ctx, url: str):
        """Set the URL for message forwarding"""
        try:
            # Validate URL format
            if not self._validate_url(url):
                await ctx.send("Invalid URL. Must be a valid HTTP/HTTPS URL.")
                return
            
            await self.config.guild(ctx.guild).forward_url.set(url)
            await ctx.send(
                "Forward URL configured successfully.\n"
                "**Note:** Forwarded messages include author IDs, usernames, avatar URLs, "
                "and message content. Ensure the target URL is trusted."
            )
        except Exception as e:
            log.error(f"Error setting URL: {e}")
            await ctx.send(f"Error setting URL: {str(e)}")
    
    @urlforward.command(name="addregex")
    @commands.guild_only()
    async def add_regex(self, ctx, *, pattern: str):
        """Add a regex pattern for message matching"""
        try:
            # Test regex pattern
            re.compile(pattern)
            
            async with self.config.guild(ctx.guild).regex_patterns() as patterns:
                if pattern not in patterns:
                    patterns.append(pattern)
                    self._clear_pattern_cache()  # Clear cache when patterns change
                    await ctx.send(f"Added regex pattern: `{pattern}`")
                else:
                    await ctx.send("Pattern already exists.")
        except re.error as e:
            await ctx.send(f"Invalid regex pattern: {str(e)}")
        except Exception as e:
            log.error(f"Error adding regex pattern: {e}")
            await ctx.send(f"Error adding pattern: {str(e)}")
    
    @urlforward.command(name="removeregex")
    @commands.guild_only()
    async def remove_regex(self, ctx, *, pattern: str):
        """Remove a regex pattern"""
        try:
            async with self.config.guild(ctx.guild).regex_patterns() as patterns:
                if pattern in patterns:
                    patterns.remove(pattern)
                    self._clear_pattern_cache()  # Clear cache when patterns change
                    await ctx.send(f"Removed regex pattern: `{pattern}`")
                else:
                    await ctx.send("Pattern not found.")
        except Exception as e:
            log.error(f"Error removing regex pattern: {e}")
            await ctx.send(f"Error removing pattern: {str(e)}")
    
    @urlforward.command(name="listregex")
    @commands.guild_only()
    async def list_regex(self, ctx):
        """List all configured regex patterns"""
        patterns = await self.config.guild(ctx.guild).regex_patterns()
        if patterns:
            pattern_list = "\n".join([f"• {pattern}" for pattern in patterns])
            await ctx.send(f"Configured regex patterns:\n{box(pattern_list)}")
        else:
            await ctx.send("No regex patterns configured.")
    
    @urlforward.command(name="attachments")
    @commands.guild_only()
    async def toggle_attachments(self, ctx, enabled: bool = None):
        """Enable/disable attachment forwarding"""
        if enabled is None:
            current = await self.config.guild(ctx.guild).forward_attachments()
            await ctx.send(f"Attachment forwarding is currently {'enabled' if current else 'disabled'}.")
        else:
            await self.config.guild(ctx.guild).forward_attachments.set(enabled)
            status = "enabled" if enabled else "disabled"
            await ctx.send(f"Attachment forwarding {status}.")
    
    @urlforward.command(name="fileext")
    @commands.guild_only()
    async def set_file_extensions(self, ctx, *extensions):
        """Set file extensions to monitor (e.g. .mp3 .wav .ogg)"""
        if not extensions:
            current = await self.config.guild(ctx.guild).file_extensions()
            ext_list = " ".join(current)
            await ctx.send(f"Current file extensions: {ext_list}")
        else:
            # Ensure extensions start with dot
            clean_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
            await self.config.guild(ctx.guild).file_extensions.set(clean_extensions)
            ext_list = " ".join(clean_extensions)
            await ctx.send(f"File extensions set to: {ext_list}")
    
    @urlforward.command(name="reaction")
    @commands.guild_only()
    async def set_reaction_emoji(self, ctx, emoji: str = None):
        """Set emoji for reaction-based re-forwarding"""
        if emoji is None:
            current = await self.config.guild(ctx.guild).reaction_emoji()
            if current:
                await ctx.send(f"Current reaction emoji: {current}")
            else:
                await ctx.send("No reaction emoji configured.")
        else:
            await self.config.guild(ctx.guild).reaction_emoji.set(emoji)
            await ctx.send(f"Reaction emoji set to: {emoji}")
    
    @urlforward.command(name="botmessages")
    @commands.guild_only()
    async def toggle_bot_messages(self, ctx, enabled: bool = None):
        """Enable/disable forwarding bot messages"""
        if enabled is None:
            current = await self.config.guild(ctx.guild).forward_bot_messages()
            await ctx.send(f"Bot message forwarding is currently {'enabled' if current else 'disabled'}.")
        else:
            await self.config.guild(ctx.guild).forward_bot_messages.set(enabled)
            status = "enabled" if enabled else "disabled"
            await ctx.send(f"Bot message forwarding {status}.")

    @urlforward.command(name="skipcommands")
    @commands.guild_only()
    async def toggle_skip_commands(self, ctx, enabled: bool = None):
        """Enable/disable skipping bot commands from forwarding.

        When enabled (default), messages that start with the bot's command
        prefix (e.g., !forward, !help) will not be forwarded.
        """
        if enabled is None:
            current = await self.config.guild(ctx.guild).skip_own_commands()
            await ctx.send(f"Skip bot commands is currently {'enabled' if current else 'disabled'}.")
        else:
            await self.config.guild(ctx.guild).skip_own_commands.set(enabled)
            status = "enabled" if enabled else "disabled"
            await ctx.send(f"Skip bot commands {status}.")

    @urlforward.command(name="enable")
    @commands.guild_only()
    async def enable_forwarding(self, ctx):
        """Enable message forwarding"""
        await self.config.guild(ctx.guild).enabled.set(True)
        await ctx.send("Message forwarding enabled.")
    
    @urlforward.command(name="disable")
    @commands.guild_only()
    async def disable_forwarding(self, ctx):
        """Disable message forwarding"""
        await self.config.guild(ctx.guild).enabled.set(False)
        await ctx.send("Message forwarding disabled.")
    
    @urlforward.command(name="status")
    @commands.guild_only()
    async def show_status(self, ctx):
        """Show current configuration status"""
        config_data = await self.config.guild(ctx.guild).all()
        
        status = "Enabled" if config_data["enabled"] else "Disabled"
        url_set = "Yes" if config_data["forward_url"] else "No"
        pattern_count = len(config_data["regex_patterns"])
        attachments = "Yes" if config_data["forward_attachments"] else "No"
        file_exts = " ".join(config_data["file_extensions"]) if config_data["file_extensions"] else "All files"
        reaction_emoji = config_data["reaction_emoji"] if config_data["reaction_emoji"] else "None"
        forwarded_count = len(config_data["forwarded_messages"])
        bot_messages = "Yes" if config_data["forward_bot_messages"] else "No"
        skip_commands = "Yes" if config_data["skip_own_commands"] else "No"

        status_msg = f"""**Forwarder Status:**
Status: {status}
URL configured: {url_set}
Regex patterns: {pattern_count}
Forward attachments: {attachments}
File extensions: {file_exts}
Forward bot messages: {bot_messages}
Skip bot commands: {skip_commands}
Reaction emoji: {reaction_emoji}
Forwarded messages tracked: {forwarded_count}"""
        
        await ctx.send(status_msg)
    
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        """Listen for messages to forward"""
        # Skip DMs
        if not message.guild:
            return
        
        try:
            config_data = await self.config.guild(message.guild).all()
            
            # Check if forwarding is enabled
            if not config_data["enabled"] or not config_data["forward_url"]:
                return
            
            # Skip bot messages unless configured to forward them
            if message.author.bot and not config_data["forward_bot_messages"]:
                return

            # Skip commands directed at this bot unless configured otherwise
            if config_data["skip_own_commands"] and await self._is_own_command(message):
                log.debug(f"Message {message.id} skipped - is a bot command")
                return

            should_forward = False
            
            # If no regex patterns are configured, forward all messages
            if not config_data["regex_patterns"]:
                should_forward = True
                log.debug(f"Message {message.id} will forward - no regex patterns configured (forward all)")
            else:
                # Check regex patterns using cached compiled patterns
                for pattern in config_data["regex_patterns"]:
                    try:
                        compiled_pattern = self._get_compiled_pattern(pattern)
                        if compiled_pattern.search(message.content):
                            should_forward = True
                            log.debug(f"Message {message.id} matched regex pattern: '{pattern}'")
                            break
                    except Exception as e:
                        log.warning(f"Error matching pattern '{pattern}': {e}")
            
            # Check attachments if enabled
            if not should_forward and config_data["forward_attachments"] and message.attachments:
                file_extensions = config_data["file_extensions"]
                
                # If no file extensions configured, forward all attachments
                if not file_extensions:
                    should_forward = True
                    log.debug(f"Message {message.id} will forward - has attachments and no file extensions filter")
                else:
                    # Check if any attachment matches the configured file extensions
                    for attachment in message.attachments:
                        if any(attachment.filename.lower().endswith(ext.lower()) for ext in file_extensions):
                            should_forward = True
                            log.debug(f"Message {message.id} will forward - attachment '{attachment.filename}' matches file extensions")
                            break
            
            if should_forward:
                success = await self._forward_message(message, config_data["forward_url"])
                if success:
                    # Track forwarded message and add confirmation emoji
                    async with self.config.guild(message.guild).forwarded_messages() as forwarded:
                        forwarded[str(message.id)] = {
                            "channel_id": str(message.channel.id),
                            "forwarded_at": datetime.now(timezone.utc).isoformat(),
                            "forward_count": 1
                        }
                    await self._add_confirmation_emoji(message, 1)
                else:
                    # Add warning emoji on failure
                    await self._add_warning_emoji(message)
            else:
                log.debug(f"Message {message.id} from #{message.channel.name} - no forward criteria met")
                # Only track message for potential reaction-based forwarding if reaction_emoji is configured
                if config_data.get("reaction_emoji"):
                    # Periodically clean up old entries to prevent unbounded growth
                    await self._cleanup_old_forwarded_messages(message.guild)
                    async with self.config.guild(message.guild).forwarded_messages() as forwarded:
                        forwarded[str(message.id)] = {
                            "channel_id": str(message.channel.id),
                            "forwarded_at": datetime.now(timezone.utc).isoformat(),
                            "forward_count": 0  # Not yet forwarded
                        }

        except Exception as e:
            log.error(f"Error processing message in guild {message.guild.id}: {e}")
    
    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        """Listen for reactions to forward messages.

        Uses raw reaction event to handle reactions on uncached/older messages.
        """
        # Skip DMs (no guild_id) and bot reactions
        if not payload.guild_id:
            return

        # Check if this is a bot reaction
        if payload.member and payload.member.bot:
            return

        try:
            guild = self.bot.get_guild(payload.guild_id)
            if not guild:
                return

            config_data = await self.config.guild(guild).all()

            # Check if reaction emoji matches configured emoji
            if not config_data["enabled"] or not config_data["reaction_emoji"] or not config_data["forward_url"]:
                return

            # Support both unicode emoji and custom emoji
            emoji_str = str(payload.emoji)
            if emoji_str != config_data["reaction_emoji"]:
                return

            message_id = str(payload.message_id)
            guild_id = str(payload.guild_id)
            lock_key = f"{guild_id}:{message_id}"

            # Prevent race condition: if this message is already being forwarded, skip
            if lock_key in self._forwarding_locks:
                log.debug(f"Message {message_id} already being forwarded, skipping duplicate")
                return

            try:
                self._forwarding_locks.add(lock_key)

                # Fetch the channel and message (needed for uncached messages)
                channel = guild.get_channel(payload.channel_id)
                if not channel:
                    channel = await self.bot.fetch_channel(payload.channel_id)

                message = await channel.fetch_message(payload.message_id)

                # Respect forward_bot_messages setting for reaction-triggered forwards
                if message.author.bot and not config_data["forward_bot_messages"]:
                    log.debug(f"Skipping reaction forward for bot message {message_id}")
                    return

                # Skip commands directed at this bot unless configured otherwise
                if config_data["skip_own_commands"] and await self._is_own_command(message):
                    log.debug(f"Skipping reaction forward for bot command {message_id}")
                    return

                # Forward the message
                success = await self._forward_message(message, config_data["forward_url"], is_reaction=True)

                if success:
                    # Update forward count and add confirmation emoji
                    async with self.config.guild(guild).forwarded_messages() as forwarded:
                        if message_id in forwarded:
                            forwarded[message_id]["forward_count"] = forwarded[message_id].get("forward_count", 0) + 1
                            forwarded[message_id]["forwarded_at"] = datetime.now(timezone.utc).isoformat()
                        else:
                            forwarded[message_id] = {
                                "channel_id": str(payload.channel_id),
                                "forwarded_at": datetime.now(timezone.utc).isoformat(),
                                "forward_count": 1
                            }
                        forward_count = forwarded[message_id]["forward_count"]

                    await self._add_confirmation_emoji(message, forward_count)
                    user_name = payload.member.name if payload.member else "unknown"
                    log.info(f"Forwarded message {message_id} (count: {forward_count}) due to {emoji_str} reaction by {user_name}")
                else:
                    # Add warning emoji on failure
                    await self._add_warning_emoji(message)
            finally:
                self._forwarding_locks.discard(lock_key)

        except discord.NotFound:
            log.warning(f"Message {payload.message_id} not found for reaction forward")
        except Exception as e:
            log.error(f"Error processing reaction in guild {payload.guild_id}: {e}")
    
    async def _forward_message(self, message: discord.Message, forward_url: str, is_reaction: bool = False) -> bool:
        """Forward message to URL.

        Returns:
            True if the message was successfully forwarded (HTTP 200/204), False otherwise.
        """
        # Check if session is initialized and not closed
        if not self.session or self.session.closed:
            log.error("Cannot forward message: aiohttp session not initialized or closed")
            return False

        try:
            # Prepare message data
            message_data = {
                "timestamp": message.created_at.isoformat(),
                "message_id": str(message.id),
                "channel_id": str(message.channel.id),
                "channel_name": message.channel.name,
                "guild_id": str(message.guild.id),
                "guild_name": message.guild.name,
                "author": {
                    "id": str(message.author.id),
                    "username": message.author.name,
                    "display_name": message.author.display_name,
                    "avatar_url": str(message.author.avatar.url) if message.author.avatar else None
                },
                "content": message.content,
                "attachments": [],
                "embeds": [],
                "jump_url": message.jump_url
            }
            
            # Add attachment information
            for attachment in message.attachments:
                attachment_data = {
                    "id": str(attachment.id),
                    "filename": attachment.filename,
                    "size": attachment.size,
                    "url": attachment.url,
                    "proxy_url": attachment.proxy_url,
                    "content_type": attachment.content_type
                }
                message_data["attachments"].append(attachment_data)
            
            # Add embed information
            for embed in message.embeds:
                embed_data = {
                    "title": embed.title,
                    "description": embed.description,
                    "url": embed.url,
                    "color": embed.color.value if embed.color else None,
                    "timestamp": embed.timestamp.isoformat() if embed.timestamp else None
                }
                message_data["embeds"].append(embed_data)
            
            # Create wrapper with forwarded_at timestamp
            url_payload = {
                "forwarded_at": datetime.now(timezone.utc).isoformat(),
                "is_reaction_forward": is_reaction,
                "message": message_data
            }

            # Log forward attempt
            forward_type = "reaction-triggered" if is_reaction else "automatic"
            log.info(f"Attempting to forward message {message.id} ({forward_type}) from #{message.channel.name} to {forward_url}")
            
            async with self.session.post(forward_url, json=url_payload) as response:
                response_text = await response.text()

                if response.status in [200, 204]:
                    log.info(f"Successfully forwarded message {message.id} - HTTP {response.status}")
                    log.debug(f"Response body: {response_text[:200]}{'...' if len(response_text) > 200 else ''}")
                    return True
                else:
                    log.warning(f"Forward failed for message {message.id} - HTTP {response.status}")
                    log.warning(f"Response body: {response_text}")
                    log.warning(f"Payload size: {len(str(url_payload))} chars, Attachments: {len(message_data['attachments'])}")
                    return False

        except Exception as e:
            log.error(f"Error forwarding message to URL: {e}")
            return False

    async def _add_confirmation_emoji(self, message: discord.Message, forward_count: int):
        """Add a confirmation emoji to indicate successful forward.

        Cycles through emojis based on forward count:
        - 1st forward: ▶️
        - 2nd forward: ⏩
        - 3rd+ forward: ⏭️

        Removes previous confirmation emoji and warning emoji before adding new one.
        """
        try:
            # Determine which emoji to use (0-indexed, clamp to last emoji for 3+)
            emoji_index = min(forward_count - 1, len(self._confirmation_emojis) - 1)
            new_emoji = self._confirmation_emojis[emoji_index]

            # Remove warning emoji if present (forward succeeded after previous failure)
            try:
                await message.remove_reaction(self._warning_emoji, self.bot.user)
            except discord.HTTPException:
                pass  # Warning emoji not present or can't be removed

            # Remove previous confirmation emoji if present (for re-forwards)
            if forward_count > 1:
                prev_emoji_index = min(forward_count - 2, len(self._confirmation_emojis) - 1)
                prev_emoji = self._confirmation_emojis[prev_emoji_index]
                try:
                    await message.remove_reaction(prev_emoji, self.bot.user)
                except discord.HTTPException:
                    pass  # Emoji not present or can't be removed

            # Add new confirmation emoji
            await message.add_reaction(new_emoji)
            log.debug(f"Added confirmation emoji {new_emoji} to message {message.id}")
        except discord.Forbidden:
            log.warning(f"Missing permissions to add reaction to message {message.id}")
        except discord.HTTPException as e:
            log.warning(f"Failed to add confirmation emoji to message {message.id}: {e}")

    async def _add_warning_emoji(self, message: discord.Message):
        """Add a warning emoji to indicate forward failure."""
        try:
            await message.add_reaction(self._warning_emoji)
            log.debug(f"Added warning emoji {self._warning_emoji} to message {message.id}")
        except discord.Forbidden:
            log.warning(f"Missing permissions to add warning reaction to message {message.id}")
        except discord.HTTPException as e:
            log.warning(f"Failed to add warning emoji to message {message.id}: {e}")
