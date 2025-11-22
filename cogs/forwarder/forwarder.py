import re
import json
import logging
import aiohttp
from typing import Optional
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
            "reaction_emoji": None,
            "forwarded_messages": {},
            "forward_bot_messages": False
        }
        self.config.register_guild(**default_guild)
        self.session = None
        self._compiled_patterns = {}  # Cache for compiled regex patterns
    
    async def cog_load(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession()
    
    async def cog_unload(self):
        """Cleanup aiohttp session"""
        if self.session:
            await self.session.close()
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        return url.startswith(("http://", "https://")) and len(url) > 10
    
    def _get_compiled_pattern(self, pattern: str) -> re.Pattern:
        """Get or compile and cache a regex pattern"""
        if pattern not in self._compiled_patterns:
            try:
                self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                # Return a pattern that never matches if compilation fails
                self._compiled_patterns[pattern] = re.compile("(?!.*)")
        return self._compiled_patterns[pattern]
    
    def _clear_pattern_cache(self):
        """Clear the compiled pattern cache"""
        self._compiled_patterns.clear()

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
            await ctx.send("Forward URL configured successfully.")
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
        
        status_msg = f"""**Forwarder Status:**
Status: {status}
URL configured: {url_set}
Regex patterns: {pattern_count}
Forward attachments: {attachments}
File extensions: {file_exts}
Forward bot messages: {bot_messages}
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
                await self._forward_message(message, config_data["forward_url"])
            else:
                log.debug(f"Message {message.id} from #{message.channel.name} - no forward criteria met")
                
                # Store message ID for potential reaction forwarding
                if config_data["reaction_emoji"]:
                    # Periodically clean up old entries to prevent unbounded growth
                    await self._cleanup_old_forwarded_messages(message.guild)

                    async with self.config.guild(message.guild).forwarded_messages() as forwarded:
                        forwarded[str(message.id)] = {
                            "channel_id": str(message.channel.id),
                            "forwarded_at": datetime.now(timezone.utc).isoformat()
                        }

        except Exception as e:
            log.error(f"Error processing message in guild {message.guild.id}: {e}")
    
    @commands.Cog.listener()
    async def on_reaction_add(self, reaction: discord.Reaction, user: discord.User):
        """Listen for reactions to re-forward messages"""
        # Skip bot reactions and DMs
        if user.bot or not reaction.message.guild:
            return
        
        try:
            config_data = await self.config.guild(reaction.message.guild).all()
            
            # Check if reaction emoji matches configured emoji
            if not config_data["enabled"] or not config_data["reaction_emoji"] or not config_data["forward_url"]:
                return
                
            # Support both unicode emoji and custom emoji
            emoji_str = str(reaction.emoji)
            if emoji_str != config_data["reaction_emoji"]:
                return
            
            # Check if this message was previously forwarded or should be forwarded now
            message_id = str(reaction.message.id)
            forwarded_messages = config_data["forwarded_messages"]
            
            if message_id in forwarded_messages:
                # Re-forward previously forwarded message
                await self._forward_message(reaction.message, config_data["forward_url"], is_reaction=True)
                log.info(f"Re-forwarded message {message_id} due to {emoji_str} reaction by {user.name}")
            else:
                # Forward any message via reaction (allows manual forwarding of unmatched messages)
                await self._forward_message(reaction.message, config_data["forward_url"], is_reaction=True)

                # Store it for future reaction tracking
                async with self.config.guild(reaction.message.guild).forwarded_messages() as forwarded:
                    forwarded[message_id] = {
                        "channel_id": str(reaction.message.channel.id),
                        "forwarded_at": datetime.now(timezone.utc).isoformat()
                    }
                log.info(f"Forwarded message {message_id} due to {emoji_str} reaction by {user.name}")
                
        except Exception as e:
            log.error(f"Error processing reaction in guild {reaction.message.guild.id}: {e}")
    
    async def _forward_message(self, message: discord.Message, forward_url: str, is_reaction: bool = False):
        """Forward message to URL"""
        # Check if session is initialized and not closed
        if not self.session or self.session.closed:
            log.error("Cannot forward message: aiohttp session not initialized or closed")
            return

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
                    log.info(f"✅ Successfully forwarded message {message.id} - HTTP {response.status}")
                    log.debug(f"Response body: {response_text[:200]}...")
                else:
                    log.warning(f"❌ Forward failed for message {message.id} - HTTP {response.status}")
                    log.warning(f"Response body: {response_text}")
                    log.warning(f"Payload size: {len(str(url_payload))} chars, Attachments: {len(message_data['attachments'])}")
                    
        except Exception as e:
            log.error(f"Error forwarding message to URL: {e}")