"""
Anti-Nuke / Anti-Raid Discord bot — entrypoint.

Run locally with:  python main.py   (after creating a .env from .env.example)
On Railway: set the DISCORD_TOKEN environment variable in the service
settings — never commit a real token to config.json or .env.

Also runs a tiny HTTP server (for Railway's public domain / cron-job.org
pings) so the service can be monitored and kept active.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

import discord
from discord.ext import commands
from aiohttp import web

try:
    # Optional: only used for local development so you don't have to
    # export DISCORD_TOKEN by hand every time. Not required on Railway,
    # which injects env vars directly.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("anti_nuke.main")

CONFIG_PATH = Path(__file__).parent / "config.json"


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict) -> None:
    # Write to a temp file then atomically swap it in, so a crash or a
    # full disk mid-write can never leave a half-written config.json.
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, CONFIG_PATH)


# Intents required:
# - members: to see joins/leaves and role/timeout changes
# - guilds: channel/role create/delete events
# - moderation: ban/unban events
# - message_content: required for prefix commands (!s ..., +s ...) to
#   read their arguments (user mentions, reasons, channel mentions, etc.)
# NOTE: "members" and "message_content" are both privileged intents —
# enable "Server Members Intent" AND "Message Content Intent" for this bot
# in the Discord Developer Portal, or the bot will fail to start / commands
# won't receive their arguments.
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.moderation = True
intents.message_content = True

bot = commands.Bot(
    # "!s <commande>" (or "+s <commande>") for every command. A command's
    # access check (owner for config commands, special role for
    # ban/kick/mute/etc — see cogs/anti_nuke.py) is enforced per-command,
    # not by which prefix was used.
    command_prefix=commands.when_mentioned_or("!s ", "+s "),
    intents=intents,
    help_command=None,
)

# Shared state attached to the bot instance so the cog can read/write it.
# config.json holds only non-secret settings (thresholds, whitelist IDs,
# log channel ID, etc). The token itself always comes from the environment.
bot.config = load_config()
bot.config_path = CONFIG_PATH
bot.save_config = lambda: save_config(bot.config)


@bot.event
async def on_ready():
    log.info("Logged in as %s (id=%s)", bot.user, bot.user.id)
    log.info("Guarding %d guild(s)", len(bot.guilds))
    if not bot.config.get("log_channel_id"):
        log.warning(
            "log_channel_id is not set in config.json — alerts will only "
            "go to the console."
        )


# --------------------------------------------------------------------- #
# Tiny health-check web server.
#
# Railway needs a process listening on $PORT for the service to get a
# public domain, and cron-job.org (or any uptime monitor) needs an HTTP
# endpoint to ping. This does not run any bot logic — it just reports
# whether the bot is currently connected to Discord.
# --------------------------------------------------------------------- #


async def health(_request: web.Request) -> web.Response:
    ok = bot.is_ready() and not bot.is_closed()
    return web.json_response({"status": "ok" if ok else "starting"}, status=200 if ok else 503)


async def start_webserver() -> None:
    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.environ.get("PORT", 8080))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info("Health check server listening on port %d", port)


async def main() -> None:
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit(
            "DISCORD_TOKEN environment variable is not set. "
            "Locally: copy .env.example to .env and fill it in. "
            "On Railway: set it under your service's Variables tab."
        )

    async with bot:
        await bot.load_extension("cogs.anti_nuke")
        await start_webserver()
        await bot.start(token)


if __name__ == "__main__":
    asyncio.run(main())
