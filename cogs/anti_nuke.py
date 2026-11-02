"""
Anti-Nuke / Anti-Raid cog.

Watches the audit log for dangerous bursts of activity (mass kicks, mass
bans, mass mutes, dangerous role grants, mass channel/role deletion,
unapproved bot additions, webhook spam) and auto-punishes the executor
once a configurable threshold is crossed inside a rolling time window.
Also flags freshly-created accounts on join.

This is defensive tooling: it never performs destructive actions on its
own initiative, only in direct response to abuse it detects, and every
action it takes is logged.
"""

from __future__ import annotations

import datetime
import logging
import time
from collections import defaultdict
from typing import Optional

import discord
from discord.ext import commands

log = logging.getLogger("anti_nuke.cog")

UTC = datetime.timezone.utc


class AntiNuke(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # {guild_id: {(executor_id, action_key): [timestamps]}}
        self._events: dict[int, dict[tuple[int, str], list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # executors currently being punished, to avoid double-punishing
        # while a punishment is in flight.
        self._punishing: set[tuple[int, int]] = set()

    # ------------------------------------------------------------------ #
    # Config helpers
    # ------------------------------------------------------------------ #

    @property
    def cfg(self) -> dict:
        return self.bot.config

    def is_whitelisted(self, guild: discord.Guild, member: Optional[discord.abc.User]) -> bool:
        if member is None:
            return False
        if member.id == guild.owner_id:
            return True
        if member.id == self.bot.user.id:
            return True
        if member.id in self.cfg.get("owner_ids", []):
            return True
        if member.id in self.cfg.get("whitelisted_users", []):
            return True
        role_ids = {r.id for r in getattr(member, "roles", [])}
        if role_ids & set(self.cfg.get("whitelisted_roles", [])):
            return True
        return False

    def is_dangerous_permissions(self, perms: discord.Permissions) -> bool:
        names = self.cfg.get("dangerous_permissions", [])
        return any(getattr(perms, name, False) for name in names)

    async def log_channel(self, guild: discord.Guild) -> Optional[discord.TextChannel]:
        chan_id = self.cfg.get("log_channel_id")
        if not chan_id:
            return None
        chan = guild.get_channel(chan_id)
        if isinstance(chan, discord.TextChannel):
            return chan
        return None

    async def alert(self, guild: discord.Guild, title: str, description: str, color: int = 0xE74C3C):
        log.warning("[%s] %s: %s", guild.name, title, description)
        chan = await self.log_channel(guild)
        if chan is None:
            return
        embed = discord.Embed(title=title, description=description, color=color)
        embed.timestamp = datetime.datetime.now(UTC)
        try:
            await chan.send(embed=embed)
        except discord.HTTPException:
            log.exception("Failed to send alert to log channel")

    # ------------------------------------------------------------------ #
    # Audit log helper
    # ------------------------------------------------------------------ #

    async def find_executor(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        target_id: Optional[int] = None,
        within_seconds: float = 8.0,
    ) -> Optional[discord.Member]:
        """Look at recent audit log entries for `action` and return the
        executor of the most recent one matching `target_id` (if given)
        within `within_seconds`. Audit log entries can lag slightly, so
        callers should expect an occasional miss."""
        now = datetime.datetime.now(UTC)
        try:
            async for entry in guild.audit_logs(limit=10, action=action):
                age = (now - entry.created_at).total_seconds()
                if age > within_seconds:
                    break
                if target_id is not None and getattr(entry.target, "id", None) != target_id:
                    continue
                if isinstance(entry.user, discord.Member):
                    return entry.user
                if entry.user is not None:
                    return guild.get_member(entry.user.id)
        except discord.Forbidden:
            log.warning("Missing 'View Audit Log' permission in %s", guild.name)
        return None

    # ------------------------------------------------------------------ #
    # Threshold tracking + punishment
    # ------------------------------------------------------------------ #

    def _record(self, guild_id: int, executor_id: int, action_key: str) -> int:
        window = self.cfg["thresholds"]["window_seconds"]
        now = time.monotonic()
        bucket = self._events[guild_id][(executor_id, action_key)]
        bucket.append(now)
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        return len(bucket)

    async def register_action(
        self,
        guild: discord.Guild,
        executor: Optional[discord.Member],
        action_key: str,
        detail: str,
    ) -> None:
        """Call this every time a watched action happens. Punishes the
        executor once their count for `action_key` crosses the configured
        threshold inside the rolling window."""
        if executor is None:
            await self.alert(
                guild,
                f"⚠️ Unattributed {action_key}",
                f"{detail}\nCould not resolve an executor from the audit log.",
            )
            return

        if self.is_whitelisted(guild, executor):
            return

        count = self._record(guild.id, executor.id, action_key)
        threshold = self.cfg["thresholds"].get(action_key)
        await self.alert(
            guild,
            f"👀 {action_key} by {executor} ({count}/{threshold})",
            detail,
            color=0xF39C12,
        )

        if threshold and count >= threshold:
            severe = action_key in self.cfg.get("severe_actions", [])
            await self.punish(guild, executor, action_key, severe)

    async def punish(
        self,
        guild: discord.Guild,
        executor: discord.Member,
        reason_key: str,
        severe: bool,
    ) -> None:
        key = (guild.id, executor.id)
        if key in self._punishing:
            return
        self._punishing.add(key)
        try:
            punishment = self.cfg.get("punishment", {})
            reason = f"Anti-nuke: threshold exceeded for '{reason_key}'"

            actions_taken = []

            if punishment.get("ban_on_severe") and severe:
                try:
                    await guild.ban(executor, reason=reason, delete_message_seconds=0)
                    actions_taken.append("banned")
                except discord.Forbidden:
                    log.warning("Cannot ban %s in %s (missing permissions / role hierarchy)", executor, guild.name)
            else:
                if punishment.get("strip_roles"):
                    removable = [
                        r for r in executor.roles
                        if r != guild.default_role and r < guild.me.top_role
                    ]
                    if removable:
                        try:
                            await executor.remove_roles(*removable, reason=reason)
                            actions_taken.append(f"stripped {len(removable)} role(s)")
                        except discord.Forbidden:
                            log.warning("Cannot strip roles from %s in %s", executor, guild.name)

                timeout_minutes = punishment.get("timeout_minutes", 0)
                if timeout_minutes:
                    try:
                        until = datetime.datetime.now(UTC) + datetime.timedelta(minutes=timeout_minutes)
                        await executor.timeout(until, reason=reason)
                        actions_taken.append(f"timed out {timeout_minutes}m")
                    except discord.Forbidden:
                        log.warning("Cannot timeout %s in %s", executor, guild.name)

            await self.alert(
                guild,
                f"🚨 PUNISHED {executor} for '{reason_key}'",
                f"Actions taken: {', '.join(actions_taken) or 'none (missing permissions — check role hierarchy)'}",
                color=0x992D22,
            )
        finally:
            self._punishing.discard(key)

    # ------------------------------------------------------------------ #
    # Listener: "piège à rats" honeypot channel
    #
    # A channel no legitimate member should ever post in (not linked
    # anywhere, or only visible via a fake "free nitro" style lure like
    # scam bots post). Anyone who sends a message there gets banned
    # instantly — no threshold, one message is enough.
    # ------------------------------------------------------------------ #

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or message.guild is None:
            return

        trap_id = self.cfg.get("trap_channel_id")
        if not trap_id or message.channel.id != trap_id:
            return

        member = message.author
        if self.is_whitelisted(message.guild, member):
            return  # so admins testing the channel don't ban themselves

        reason = "Anti-raid: posted in the honeypot/trap channel"
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        try:
            await message.guild.ban(member, reason=reason, delete_message_seconds=86400)
            outcome = "banned, last 24h of their messages purged"
        except discord.Forbidden:
            outcome = "COULD NOT BAN (missing permissions / role hierarchy)"

        await self.alert(
            message.guild,
            f"🪤 Trap channel triggered: {member}",
            f"{member} ({member.id}) posted in <#{trap_id}>. Result: {outcome}.",
            color=0x992D22,
        )

    # ------------------------------------------------------------------ #
    # Listeners: members joining / leaving
    # ------------------------------------------------------------------ #

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        guild = member.guild

        # --- Unapproved bot added to the server ---------------------- #
        if member.bot:
            adder = await self.find_executor(guild, discord.AuditLogAction.bot_add, member.id)
            if self.is_whitelisted(guild, adder):
                return
            detail = f"Bot {member} ({member.id}) was added by {adder or 'unknown'}."
            if not self.is_whitelisted(guild, adder):
                try:
                    await guild.kick(member, reason="Anti-nuke: unapproved bot addition")
                    detail += " Bot was kicked."
                except discord.Forbidden:
                    detail += " Could not kick the bot (missing permissions)."
            await self.register_action(guild, adder, "bot_adds", detail)
            return

        # --- Freshly created account -------------------------------- #
        min_days = self.cfg.get("new_account_min_age_days", 0)
        if min_days > 0:
            age_days = (datetime.datetime.now(UTC) - member.created_at).days
            if age_days < min_days:
                action = self.cfg.get("new_account_action", "flag")
                detail = f"{member} ({member.id}) account age: {age_days}d (min {min_days}d)."
                if action == "kick":
                    try:
                        await member.kick(reason="Anti-raid: account too new")
                        detail += " Kicked."
                    except discord.Forbidden:
                        detail += " Could not kick (missing permissions)."
                elif action == "ban":
                    try:
                        await member.ban(reason="Anti-raid: account too new", delete_message_seconds=0)
                        detail += " Banned."
                    except discord.Forbidden:
                        detail += " Could not ban (missing permissions)."
                await self.alert(guild, "🆕 New account joined", detail, color=0xF1C40F)

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member):
        guild = member.guild
        executor = await self.find_executor(guild, discord.AuditLogAction.kick, member.id)
        if executor is None:
            return  # ordinary leave, not a kick
        await self.register_action(
            guild, executor, "kicks", f"{executor} kicked {member} ({member.id})."
        )

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User):
        executor = await self.find_executor(guild, discord.AuditLogAction.ban, user.id)
        await self.register_action(
            guild, executor, "bans", f"{executor} banned {user} ({user.id})."
        )

    # ------------------------------------------------------------------ #
    # Listener: member update (dangerous roles + timeouts/mutes)
    # ------------------------------------------------------------------ #

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):
        guild = after.guild

        # --- Dangerous role grant ------------------------------------ #
        added_roles = [r for r in after.roles if r not in before.roles]
        dangerous_added = [r for r in added_roles if self.is_dangerous_permissions(r.permissions)]
        if dangerous_added:
            executor = await self.find_executor(guild, discord.AuditLogAction.member_role_update, after.id)
            if not self.is_whitelisted(guild, executor):
                role_names = ", ".join(r.name for r in dangerous_added)
                detail = f"{executor} granted {after} dangerous role(s): {role_names}."
                try:
                    removable = [r for r in dangerous_added if r < guild.me.top_role]
                    if removable:
                        await after.remove_roles(*removable, reason="Anti-nuke: unapproved dangerous role grant")
                        detail += " Role(s) reverted."
                except discord.Forbidden:
                    detail += " Could not revert (missing permissions)."
                await self.register_action(guild, executor, "dangerous_role_grants", detail)

        # --- Timeout / mute -------------------------------------------- #
        was_muted = before.timed_out_until is not None and before.timed_out_until > datetime.datetime.now(UTC)
        is_muted = after.timed_out_until is not None and after.timed_out_until > datetime.datetime.now(UTC)
        if is_muted and not was_muted:
            executor = await self.find_executor(guild, discord.AuditLogAction.member_update, after.id)
            await self.register_action(
                guild, executor, "mutes", f"{executor} timed out {after} ({after.id})."
            )

    # ------------------------------------------------------------------ #
    # Listeners: channels / roles / webhooks (raid-style destruction)
    # ------------------------------------------------------------------ #

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel):
        executor = await self.find_executor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
        await self.register_action(
            channel.guild, executor, "channel_deletes",
            f"{executor} deleted channel #{channel.name}.",
        )

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel):
        executor = await self.find_executor(channel.guild, discord.AuditLogAction.channel_create, channel.id)
        await self.register_action(
            channel.guild, executor, "channel_creates",
            f"{executor} created channel #{channel.name}.",
        )

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role):
        executor = await self.find_executor(role.guild, discord.AuditLogAction.role_delete, role.id)
        await self.register_action(
            role.guild, executor, "role_deletes", f"{executor} deleted role '{role.name}'."
        )

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role):
        executor = await self.find_executor(role.guild, discord.AuditLogAction.role_create, role.id)
        await self.register_action(
            role.guild, executor, "role_creates", f"{executor} created role '{role.name}'."
        )

    @commands.Cog.listener()
    async def on_webhooks_update(self, channel: discord.abc.GuildChannel):
        executor = await self.find_executor(channel.guild, discord.AuditLogAction.webhook_create)
        if executor is None:
            return
        await self.register_action(
            channel.guild, executor, "webhook_creates",
            f"{executor} created/modified a webhook in #{channel.name}.",
        )

    # ------------------------------------------------------------------ #
    # Management commands (owner / server owner only)
    # ------------------------------------------------------------------ #

    def _is_authorized(self, ctx: commands.Context) -> bool:
        return (
            ctx.author.id == ctx.guild.owner_id
            or ctx.author.id in self.cfg.get("owner_ids", [])
        )

    @commands.command(name="an_whitelist_user")
    async def whitelist_user(self, ctx: commands.Context, user: discord.Member):
        if not self._is_authorized(ctx):
            return await ctx.reply("You are not authorized to change anti-nuke settings.")
        wl = self.cfg.setdefault("whitelisted_users", [])
        if user.id not in wl:
            wl.append(user.id)
            self.bot.save_config()
        await ctx.reply(f"✅ {user} added to the anti-nuke whitelist.")

    @commands.command(name="an_unwhitelist_user")
    async def unwhitelist_user(self, ctx: commands.Context, user: discord.Member):
        if not self._is_authorized(ctx):
            return await ctx.reply("You are not authorized to change anti-nuke settings.")
        wl = self.cfg.setdefault("whitelisted_users", [])
        if user.id in wl:
            wl.remove(user.id)
            self.bot.save_config()
        await ctx.reply(f"✅ {user} removed from the anti-nuke whitelist.")

    @commands.command(name="an_whitelist_role")
    async def whitelist_role(self, ctx: commands.Context, role: discord.Role):
        if not self._is_authorized(ctx):
            return await ctx.reply("You are not authorized to change anti-nuke settings.")
        wl = self.cfg.setdefault("whitelisted_roles", [])
        if role.id not in wl:
            wl.append(role.id)
            self.bot.save_config()
        await ctx.reply(f"✅ Role {role.name} added to the anti-nuke whitelist.")

    @commands.command(name="an_set_log_channel")
    async def set_log_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        if not self._is_authorized(ctx):
            return await ctx.reply("You are not authorized to change anti-nuke settings.")
        self.cfg["log_channel_id"] = channel.id
        self.bot.save_config()
        await ctx.reply(f"✅ Log channel set to {channel.mention}.")

    @commands.command(name="an_set_trap_channel")
    async def set_trap_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        if not self._is_authorized(ctx):
            return await ctx.reply("You are not authorized to change anti-nuke settings.")
        self.cfg["trap_channel_id"] = channel.id
        self.bot.save_config()
        await ctx.reply(
            f"🪤 Trap channel set to {channel.mention} — anyone who posts there now gets "
            "banned instantly. Make sure it's hidden from everyone except "
            "@everyone/scam-bait visibility, and that none of your real mods/admins "
            "would ever post in it (whitelisted users are exempt)."
        )

    @commands.command(name="an_status")
    async def status(self, ctx: commands.Context):
        t = self.cfg["thresholds"]
        lines = [f"**{k}**: {v}" for k, v in t.items()]
        embed = discord.Embed(
            title="Anti-Nuke status",
            description="\n".join(lines),
            color=0x2ECC71,
        )
        embed.add_field(
            name="Whitelisted users", value=str(len(self.cfg.get("whitelisted_users", [])))
        )
        embed.add_field(
            name="Whitelisted roles", value=str(len(self.cfg.get("whitelisted_roles", [])))
        )
        trap_id = self.cfg.get("trap_channel_id")
        embed.add_field(
            name="Trap channel", value=f"<#{trap_id}>" if trap_id else "not set"
        )
        await ctx.reply(embed=embed)


async def setup(bot: commands.Bot):
    await bot.add_cog(AntiNuke(bot))
