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
import json
import logging
import re
import time
from collections import defaultdict
from typing import Optional

import discord
from discord.ext import commands

log = logging.getLogger("anti_nuke.cog")

UTC = datetime.timezone.utc

# --------------------------------------------------------------------- #
# Every setting of config.json that can be edited from Discord.
# `!s set <key> <value>` handles SCALAR_SETTINGS (dotted keys address
# the nested "punishment" / "thresholds" sections), `!s add`,
# `!s remove` and `!s clear` handle LIST_SETTINGS.
# --------------------------------------------------------------------- #

ACTION_KEYS = (
    "kicks",
    "bans",
    "mutes",
    "dangerous_role_grants",
    "channel_deletes",
    "channel_creates",
    "role_deletes",
    "role_creates",
    "bot_adds",
    "webhook_creates",
)

SCALAR_SETTINGS: dict[str, tuple] = {
    "log_channel_id": ("channel",),
    "trap_channel_id": ("channel",),
    "alert_ping_user_id": ("user",),
    "special_staff_role_id": ("role",),
    "new_account_min_age_days": ("int", 0, 3650),
    "new_account_action": ("choice", ("flag", "kick", "ban")),
    "punishment.strip_roles": ("bool",),
    "punishment.timeout_minutes": ("int", 0, 40320),  # Discord max = 28 days
    "punishment.ban_on_severe": ("bool",),
    "thresholds.window_seconds": ("int", 1, 3600),
    **{f"thresholds.{k}": ("int", 0, 1000) for k in ACTION_KEYS},
}

LIST_SETTINGS: dict[str, str] = {
    "owner_ids": "user",
    "whitelisted_users": "user",
    "whitelisted_roles": "role",
    "dangerous_permissions": "permission",
    "severe_actions": "action",
}

VALID_PERMISSIONS = frozenset(name for name, _ in discord.Permissions.none())

_TRUE = {"true", "on", "yes", "y", "1", "oui", "vrai"}
_FALSE = {"false", "off", "no", "n", "0", "non", "faux"}
_OFF = {"none", "off", "disable", "disabled", "null"}
_ID_RE = re.compile(r"<(?:@[!&]?|#)(\d+)>|(\d+)")


CONFIG_COMMANDS = frozenset({
    "status", "help", "set", "add", "remove", "clear", "reload",
    "whitelist_user", "unwhitelist_user", "whitelist_role", "unwhitelist_role",
    "set_log_channel", "set_trap_channel",
})


def parse_id(raw: str) -> int:
    m = _ID_RE.fullmatch(raw.strip())
    if not m:
        raise ValueError(f"`{raw}` is not a valid ID or mention.")
    return int(m.group(1) or m.group(2))


def parse_item(
    kind: str,
    raw: str,
    guild: Optional[discord.Guild] = None,
    allow_zero: bool = False,
):
    """Parse + validate one value. When `guild` is None, only the syntax is
    checked (used for removals, so stale/deleted IDs can still be removed)."""
    raw = raw.strip()
    if kind == "permission":
        name = raw.lower()
        if name not in VALID_PERMISSIONS:
            raise ValueError(f"`{raw}` is not a Discord permission name (e.g. `ban_members`).")
        return name
    if kind == "action":
        name = raw.lower()
        if name not in ACTION_KEYS:
            raise ValueError(f"`{raw}` is not a watched action. Valid: {', '.join(ACTION_KEYS)}.")
        return name

    id_ = parse_id(raw)
    if id_ == 0:
        if allow_zero:
            return 0
        raise ValueError("0 is not a valid ID here.")
    if guild is None:
        return id_
    if kind == "channel" and not isinstance(guild.get_channel(id_), discord.TextChannel):
        raise ValueError(f"`{raw}` is not a text channel of this server.")
    if kind == "role":
        if id_ == guild.id:
            raise ValueError("@everyone cannot be used here.")
        if guild.get_role(id_) is None:
            raise ValueError(f"`{raw}` is not a role of this server.")
    return id_


def parse_scalar(spec: tuple, raw: str, guild: discord.Guild):
    kind = spec[0]
    raw = raw.strip()
    if kind in ("channel", "role", "user"):
        if raw.lower() in _OFF:
            raw = "0"
        return parse_item(kind, raw, guild, allow_zero=True)
    if kind == "int":
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"`{raw}` is not a whole number.") from None
        lo, hi = spec[1], spec[2]
        if not lo <= value <= hi:
            raise ValueError(f"Value must be between {lo} and {hi}.")
        return value
    if kind == "bool":
        low = raw.lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
        raise ValueError("Use `true` or `false` (also: on/off, yes/no, oui/non).")
    if kind == "choice":
        low = raw.lower()
        if low not in spec[1]:
            raise ValueError(f"Must be one of: {', '.join(spec[1])}.")
        return low
    raise ValueError(f"Unsupported setting type {kind!r}.")


def fmt_ref(kind: str, value) -> str:
    if kind == "channel":
        return f"<#{value}>"
    if kind == "role":
        return f"<@&{value}>"
    if kind == "user":
        return f"<@{value}>"
    return f"`{value}`"


def config_admin():
    """Command check for every an_* command: server owner or config.json
    `owner_ids` only."""

    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            raise commands.NoPrivateMessage()
        return (
            ctx.author.id == ctx.guild.owner_id
            or ctx.author.id in ctx.bot.config.get("owner_ids", [])
        )

    return commands.check(predicate)


def has_special_role():
    """Command check: only members with the configured special staff role
    (bot.config['special_staff_role_id']) can run the command. Used for the
    +s moderation commands — unlike the an_* config commands, there's no
    owner/server-owner fallback here, it's role-only by design."""

    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None or not isinstance(ctx.author, discord.Member):
            return False
        role_id = ctx.bot.config.get("special_staff_role_id")
        if not role_id:
            return False
        return any(r.id == role_id for r in ctx.author.roles)

    return commands.check(predicate)


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

    def build_cv2(
        self,
        title: str,
        description: str,
        color: int,
        mention_id: Optional[int] = None,
    ) -> discord.ui.LayoutView:
        """Build a Components V2 message (the modern replacement for
        discord.Embed) — a LayoutView holding a Container with an accent
        colour, a heading, a body and a live Discord timestamp. Used for
        every message the bot sends (alerts, command replies)."""
        view = discord.ui.LayoutView()
        container = discord.ui.Container(accent_color=discord.Color(color))
        if mention_id:
            container.add_item(discord.ui.TextDisplay(f"<@{mention_id}>"))
        container.add_item(discord.ui.TextDisplay(f"# {title}"))
        container.add_item(discord.ui.TextDisplay(description or "\u200b"))
        container.add_item(discord.ui.Separator())
        ts = int(datetime.datetime.now(UTC).timestamp())
        container.add_item(discord.ui.TextDisplay(f"<t:{ts}:f>"))
        view.add_item(container)
        return view

    async def alert(
        self,
        guild: discord.Guild,
        title: str,
        description: str,
        color: int = 0xE74C3C,
        ping: bool = False,
    ):
        log.warning("[%s] %s: %s", guild.name, title, description)
        chan = await self.log_channel(guild)
        if chan is None:
            return

        ping_id = self.cfg.get("alert_ping_user_id") if ping else None
        view = self.build_cv2(title, description, color, mention_id=ping_id)

        try:
            # content/embeds can't be combined with a Components V2 view —
            # the mention (if any) is already inside the container as text.
            await chan.send(view=view, allowed_mentions=discord.AllowedMentions(users=True))
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
            severe = action_key in self.cfg.get("severe_actions", [])
            await self.alert(
                guild,
                f"⚠️ Unattributed {action_key}",
                f"{detail}\nCould not resolve an executor from the audit log.",
                ping=severe,
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
                ping=True,
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
            ping=True,
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
    # Management commands (server owner / owner_ids only)
    #
    # Everything in config.json can be changed from Discord:
    #   !s status                         show the whole config
    #   !s set <key> <value>              change any single setting
    #   !s add / !s remove <list> <...>  edit a list (whitelist, owners...)
    #   !s clear <list>                   empty a list
    #   !s reload                         re-read config.json from disk
    #   !s help                           list every key
    # ------------------------------------------------------------------ #

    def _is_authorized(self, ctx: commands.Context) -> bool:
        return (
            ctx.guild is not None
            and (
                ctx.author.id == ctx.guild.owner_id
                or ctx.author.id in self.cfg.get("owner_ids", [])
            )
        )

    async def _say(self, ctx: commands.Context, text: str):
        # Replies may contain <@id> mentions: never actually ping anyone.
        return await ctx.reply(text, allowed_mentions=discord.AllowedMentions.none())

    async def _say_cv2(self, ctx: commands.Context, title: str, description: str, color: int):
        view = self.build_cv2(title, description, color)
        return await ctx.reply(view=view, allowed_mentions=discord.AllowedMentions.none())

    def _get(self, key: str):
        section, _, name = key.partition(".")
        if name:
            return self.cfg.get(section, {}).get(name)
        return self.cfg.get(key)

    def _put(self, key: str, value) -> None:
        section, _, name = key.partition(".")
        if name:
            self.cfg.setdefault(section, {})[name] = value
        else:
            self.cfg[key] = value

    def _save(self) -> str:
        """Persist config.json. Returns a suffix to append to the reply."""
        try:
            self.bot.save_config()
            return ""
        except OSError as exc:
            log.exception("Could not write config.json")
            return f"\n⚠️ Applied in memory but could NOT be saved to config.json ({exc})."

    def _fmt_scalar(self, key: str) -> str:
        spec = SCALAR_SETTINGS[key]
        value = self._get(key)
        if value is None:
            return "—"
        kind = spec[0]
        if kind in ("channel", "role", "user"):
            return fmt_ref(kind, value) if value else "not set"
        if kind == "bool":
            return "on" if value else "off"
        return f"`{value}`"

    def _config_chunks(self) -> list[str]:
        groups: dict[str, list[str]] = {"General": [], "Punishment": [], "Thresholds": []}
        for key in SCALAR_SETTINGS:
            if key.startswith("punishment."):
                group = "Punishment"
            elif key.startswith("thresholds."):
                group = "Thresholds"
            else:
                group = "General"
            groups[group].append(f"`{key}`: {self._fmt_scalar(key)}")

        blocks = [f"**{name}**\n" + "\n".join(lines) for name, lines in groups.items()]
        for key, kind in LIST_SETTINGS.items():
            values = self.cfg.get(key, [])
            shown = ", ".join(fmt_ref(kind, v) for v in values[:15]) or "none"
            if len(values) > 15:
                shown += f" … (+{len(values) - 15} more)"
            blocks.append(f"**{key}** ({len(values)})\n{shown}")

        # Components V2 caps the text per message, so split into chunks.
        chunks: list[str] = []
        current = ""
        for block in blocks:
            if current and len(current) + len(block) + 2 > 3000:
                chunks.append(current)
                current = block
            else:
                current = f"{current}\n\n{block}" if current else block
        chunks.append(current)
        return chunks

    async def cog_command_error(self, ctx: commands.Context, error: commands.CommandError):
        cmd = ctx.command
        if cmd is None or cmd.name not in CONFIG_COMMANDS:
            return  # +s commands have their own handler
        if isinstance(error, commands.NoPrivateMessage):
            return await self._say(ctx, "This command only works inside a server.")
        if isinstance(error, commands.CheckFailure):
            return await self._say(ctx, "You are not authorized to change anti-nuke settings.")
        if isinstance(
            error,
            (commands.MissingRequiredArgument, commands.BadArgument, commands.TooManyArguments),
        ):
            return await self._say(
                ctx, f"❌ {error}\nUsage: `!s {cmd.qualified_name} {cmd.signature}`".strip()
            )
        log.exception("Unhandled error in %s", cmd.name, exc_info=error)
        await self._say(ctx, "❌ Unexpected error — check the console.")

    # ---- read ---------------------------------------------------------- #

    @commands.command(name="status", aliases=["config"])
    @config_admin()
    async def status(self, ctx: commands.Context):
        """Show the whole configuration."""
        chunks = self._config_chunks()
        for i, text in enumerate(chunks, 1):
            title = "Anti-Nuke config" + (f" ({i}/{len(chunks)})" if len(chunks) > 1 else "")
            await self._say_cv2(ctx, title, text, 0x2ECC71)

    @commands.command(name="help")
    @config_admin()
    async def an_help(self, ctx: commands.Context):
        """List every command and every editable key."""
        text = (
            "`!s status` — show the whole config\n"
            "`!s set <key> <value>` — change one setting (`0` or `off` disables an ID setting)\n"
            "`!s add <list> <value...>` — add to a list\n"
            "`!s remove <list> <value...>` — remove from a list\n"
            "`!s clear <list>` — empty a list\n"
            "`!s reload` — re-read config.json from disk\n"
            "Shortcuts: `!s whitelist_user`, `!s unwhitelist_user`, `!s whitelist_role`, "
            "`!s unwhitelist_role`, `!s set_log_channel`, `!s set_trap_channel`\n\n"
            f"**Keys for `!s set`**\n{', '.join(f'`{k}`' for k in SCALAR_SETTINGS)}\n\n"
            f"**Lists for `!s add` / `!s remove` / `!s clear`**\n"
            f"{', '.join(f'`{k}`' for k in LIST_SETTINGS)}"
        )
        await self._say_cv2(ctx, "Anti-Nuke commands", text, 0x3498DB)

    # ---- write: scalars ------------------------------------------------ #

    @commands.command(name="set")
    @config_admin()
    async def an_set(self, ctx: commands.Context, key: str, *, value: str):
        """Change any single setting: !s set <key> <value>"""
        key = key.lower()
        if key in LIST_SETTINGS:
            return await self._say(ctx, f"`{key}` is a list — use `!s add` / `!s remove` / `!s clear`.")
        spec = SCALAR_SETTINGS.get(key)
        if spec is None:
            return await self._say(
                ctx, f"❌ Unknown key `{key}`. Use `!s help` to see every key."
            )
        try:
            new = parse_scalar(spec, value, ctx.guild)
        except ValueError as exc:
            return await self._say(ctx, f"❌ {exc}")

        old = self._fmt_scalar(key)
        self._put(key, new)
        suffix = self._save()
        await self._say(ctx, f"✅ `{key}`: {old} → {self._fmt_scalar(key)}{suffix}")

    # ---- write: lists -------------------------------------------------- #

    @commands.command(name="add")
    @config_admin()
    async def an_add(self, ctx: commands.Context, key: str, *values: str):
        """Add one or several values to a list: !s add <list> <value...>"""
        key = key.lower()
        kind = LIST_SETTINGS.get(key)
        if kind is None or not values:
            return await self._say(
                ctx,
                f"Usage: `!s add <list> <value...>` — lists: {', '.join(f'`{k}`' for k in LIST_SETTINGS)}",
            )
        current = self.cfg.setdefault(key, [])
        added, skipped, errors = [], [], []
        for raw in values:
            try:
                item = parse_item(kind, raw, ctx.guild)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if item in current:
                skipped.append(fmt_ref(kind, item))
            else:
                current.append(item)
                added.append(fmt_ref(kind, item))

        parts = []
        if added:
            parts.append(f"✅ Added to `{key}`: {', '.join(added)}" + self._save())
        if skipped:
            parts.append(f"ℹ️ Already present: {', '.join(skipped)}")
        parts.extend(f"❌ {e}" for e in errors)
        await self._say(ctx, "\n".join(parts))

    @commands.command(name="remove")
    @config_admin()
    async def an_remove(self, ctx: commands.Context, key: str, *values: str):
        """Remove one or several values from a list: !s remove <list> <value...>"""
        key = key.lower()
        kind = LIST_SETTINGS.get(key)
        if kind is None or not values:
            return await self._say(
                ctx,
                f"Usage: `!s remove <list> <value...>` — lists: {', '.join(f'`{k}`' for k in LIST_SETTINGS)}",
            )
        current = self.cfg.setdefault(key, [])
        removed, missing, errors = [], [], []
        for raw in values:
            try:
                item = parse_item(kind, raw)  # syntax only: stale IDs can be removed
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if item in current:
                current.remove(item)
                removed.append(fmt_ref(kind, item))
            else:
                missing.append(fmt_ref(kind, item))

        parts = []
        if removed:
            parts.append(f"✅ Removed from `{key}`: {', '.join(removed)}" + self._save())
        if missing:
            parts.append(f"ℹ️ Not in the list: {', '.join(missing)}")
        parts.extend(f"❌ {e}" for e in errors)
        await self._say(ctx, "\n".join(parts))

    @commands.command(name="clear")
    @config_admin()
    async def an_clear(self, ctx: commands.Context, key: str):
        """Empty a list: !s clear <list>"""
        key = key.lower()
        if key not in LIST_SETTINGS:
            return await self._say(
                ctx, f"Usage: `!s clear <list>` — lists: {', '.join(f'`{k}`' for k in LIST_SETTINGS)}"
            )
        count = len(self.cfg.get(key, []))
        self.cfg[key] = []
        await self._say(ctx, f"✅ `{key}` cleared ({count} entr{'y' if count == 1 else 'ies'} removed).{self._save()}")

    # ---- reload -------------------------------------------------------- #

    @commands.command(name="reload")
    @config_admin()
    async def an_reload(self, ctx: commands.Context):
        """Re-read config.json from disk (after editing the file by hand)."""
        try:
            with open(self.bot.config_path, "r", encoding="utf-8") as f:
                fresh = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            return await self._say(ctx, f"❌ Could not reload config.json: {exc}")
        self.bot.config.clear()
        self.bot.config.update(fresh)
        await self._say(ctx, "✅ config.json reloaded from disk.")

    # ---- shortcuts (kept for backwards compatibility) ------------------ #

    @commands.command(name="whitelist_user")
    @config_admin()
    async def whitelist_user(self, ctx: commands.Context, user: discord.Member):
        wl = self.cfg.setdefault("whitelisted_users", [])
        if user.id not in wl:
            wl.append(user.id)
        await self._say(ctx, f"✅ {user} added to the anti-nuke whitelist.{self._save()}")

    @commands.command(name="unwhitelist_user")
    @config_admin()
    async def unwhitelist_user(self, ctx: commands.Context, user: discord.Member):
        wl = self.cfg.setdefault("whitelisted_users", [])
        if user.id in wl:
            wl.remove(user.id)
        await self._say(ctx, f"✅ {user} removed from the anti-nuke whitelist.{self._save()}")

    @commands.command(name="whitelist_role")
    @config_admin()
    async def whitelist_role(self, ctx: commands.Context, role: discord.Role):
        if role.id == ctx.guild.id:
            return await self._say(ctx, "❌ @everyone cannot be whitelisted — that would disable the protection.")
        wl = self.cfg.setdefault("whitelisted_roles", [])
        if role.id not in wl:
            wl.append(role.id)
        await self._say(ctx, f"✅ Role {role.name} added to the anti-nuke whitelist.{self._save()}")

    @commands.command(name="unwhitelist_role")
    @config_admin()
    async def unwhitelist_role(self, ctx: commands.Context, role: discord.Role):
        wl = self.cfg.setdefault("whitelisted_roles", [])
        if role.id in wl:
            wl.remove(role.id)
        await self._say(ctx, f"✅ Role {role.name} removed from the anti-nuke whitelist.{self._save()}")

    @commands.command(name="set_log_channel")
    @config_admin()
    async def set_log_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        self.cfg["log_channel_id"] = channel.id
        await self._say(ctx, f"✅ Log channel set to {channel.mention}.{self._save()}")

    @commands.command(name="set_trap_channel")
    @config_admin()
    async def set_trap_channel(self, ctx: commands.Context, channel: discord.TextChannel):
        self.cfg["trap_channel_id"] = channel.id
        await self._say(
            ctx,
            f"🪤 Trap channel set to {channel.mention} — anyone who posts there now gets "
            "banned instantly. Make sure it's hidden from everyone except "
            "@everyone/scam-bait visibility, and that none of your real mods/admins "
            f"would ever post in it (whitelisted users are exempt).{self._save()}",
        )


    # ------------------------------------------------------------------ #
    # "+s" commands — usable only by members with special_staff_role_id
    # ------------------------------------------------------------------ #

    async def cv2_reply(self, ctx: commands.Context, title: str, description: str, color: int):
        view = self.build_cv2(title, description, color)
        await ctx.reply(view=view)

    @commands.command(name="ban")
    @has_special_role()
    async def s_ban(self, ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
        try:
            await ctx.guild.ban(member, reason=f"By {ctx.author}: {reason}", delete_message_seconds=0)
            await self.cv2_reply(ctx, "🔨 Member banned", f"{member} ({member.id}) was banned.\nReason: {reason}", 0x992D22)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not ban", f"Missing permissions, or {member}'s role is above mine.", 0xE74C3C)

    @commands.command(name="unban")
    @has_special_role()
    async def s_unban(self, ctx: commands.Context, user_id: int, *, reason: str = "No reason provided"):
        try:
            await ctx.guild.unban(discord.Object(id=user_id), reason=f"By {ctx.author}: {reason}")
            await self.cv2_reply(ctx, "✅ Member unbanned", f"User ID {user_id} was unbanned.\nReason: {reason}", 0x2ECC71)
        except discord.NotFound:
            await self.cv2_reply(ctx, "❌ Could not unban", f"No ban found for user ID {user_id}.", 0xE74C3C)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not unban", "Missing permissions.", 0xE74C3C)

    @commands.command(name="kick")
    @has_special_role()
    async def s_kick(self, ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
        try:
            await member.kick(reason=f"By {ctx.author}: {reason}")
            await self.cv2_reply(ctx, "👢 Member kicked", f"{member} ({member.id}) was kicked.\nReason: {reason}", 0xF39C12)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not kick", f"Missing permissions, or {member}'s role is above mine.", 0xE74C3C)

    @commands.command(name="mute")
    @has_special_role()
    async def s_mute(self, ctx: commands.Context, member: discord.Member, minutes: int = 60, *, reason: str = "No reason provided"):
        try:
            until = datetime.datetime.now(UTC) + datetime.timedelta(minutes=minutes)
            await member.timeout(until, reason=f"By {ctx.author}: {reason}")
            await self.cv2_reply(ctx, "🔇 Member muted", f"{member} ({member.id}) timed out for {minutes}m.\nReason: {reason}", 0xF39C12)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not mute", f"Missing permissions, or {member}'s role is above mine.", 0xE74C3C)

    @commands.command(name="unmute")
    @has_special_role()
    async def s_unmute(self, ctx: commands.Context, member: discord.Member):
        try:
            await member.timeout(None, reason=f"By {ctx.author}")
            await self.cv2_reply(ctx, "🔊 Member unmuted", f"{member} ({member.id}) is no longer timed out.", 0x2ECC71)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not unmute", f"Missing permissions, or {member}'s role is above mine.", 0xE74C3C)

    @commands.command(name="clear")
    @has_special_role()
    async def s_clear(self, ctx: commands.Context, amount: int = 10):
        amount = max(1, min(amount, 100))
        try:
            deleted = await ctx.channel.purge(limit=amount + 1)  # +1 to also remove the command message
            await self.cv2_reply(ctx, "🧹 Messages cleared", f"Deleted {len(deleted) - 1} message(s) in {ctx.channel.mention}.", 0x2ECC71)
        except discord.Forbidden:
            await self.cv2_reply(ctx, "❌ Could not clear", "Missing 'Manage Messages' permission in this channel.", 0xE74C3C)

    @s_ban.error
    @s_unban.error
    @s_kick.error
    @s_mute.error
    @s_unmute.error
    @s_clear.error
    async def special_command_error(self, ctx: commands.Context, error: commands.CommandError):
        if isinstance(error, commands.CheckFailure):
            return  # silently ignore — don't reveal the command exists to non-staff
        if isinstance(error, commands.MemberNotFound):
            return await self.cv2_reply(ctx, "❌ Member not found", str(error), 0xE74C3C)
        if isinstance(error, commands.MissingRequiredArgument):
            return await self.cv2_reply(ctx, "❌ Missing argument", str(error), 0xE74C3C)
        log.exception("Unhandled error in +s command", exc_info=error)
        await self.cv2_reply(ctx, "❌ Unexpected error", str(error), 0xE74C3C)


async def setup(bot: commands.Bot):
    await bot.add_cog(AntiNuke(bot))
