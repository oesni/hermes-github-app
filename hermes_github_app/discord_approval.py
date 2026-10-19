"""Discord-only host confirmation using the running Hermes discord.py client."""
from __future__ import annotations
import asyncio
import secrets
import sys
import threading
import time
import unicodedata


def active_discord_client():
    """Read the live gateway; never create a bot or load a token ourselves."""
    module = sys.modules.get('gateway.run')
    if module is None:
        return None
    runner = module._gateway_runner_ref()
    if runner is None:
        return None
    from gateway.config import Platform
    # Multiplexed profiles share process globals but not identity/policy; this
    # adapter only supports a single active gateway profile. Named profiles
    # still use runner.adapters, not the secondary-profile mapping.
    if getattr(runner.config, 'multiplex_profiles', False):
        return None
    adapters = runner.adapters
    adapter = adapters.get(Platform.DISCORD)
    client = getattr(adapter, '_client', None)
    if client is None or not client.is_ready() or client.is_closed():
        return None
    return client


class DiscordApprovalAdapter:
    def __init__(self, approver_ids, client_provider=active_discord_client):
        self.approver_ids = frozenset(str(x) for x in approver_ids)
        self._client_provider = client_provider
        self._lock = threading.Lock()
        self._requests = {}

    def available(self):
        try:
            client = self._client_provider()
            return bool(self.approver_ids and client is not None and client.loop.is_running()
                        and not _same_loop(client.loop))
        except Exception:
            return False

    def present(self, request_id, target, deadline, on_decision):
        client = self._client_provider()
        if client is None or not self.approver_ids:
            return False
        future = None
        try:
            loop = client.loop
            if not loop.is_running() or _same_loop(loop):
                return False
            with self._lock:
                if request_id in self._requests:
                    return False
                state = {'active': True, 'messages': [], 'views': [], 'client': client, 'deadline': deadline, 'presented': False}
                self._requests[request_id] = state
            future = asyncio.run_coroutine_threadsafe(self._present(client, request_id, target, state, on_decision), loop)
            return future.result(timeout=20)
        except Exception:
            if future is not None:
                future.cancel()
            self.finish(request_id, 'unavailable')
            return False

    async def _present(self, client, request_id, target, state, on_decision):
        import discord
        # Render the complete approved tuple separately from untrusted author text.
        # A bounded embed avoids Discord's 2000-character message limit even for
        # maximum-length escaped branch names. Author controls cannot spoof rows.
        raw_title = ''.join(' ' if ch.isspace() else ch for ch in str(target['title'])
                            if unicodedata.category(ch) not in {'Cc', 'Cf'} or ch.isspace())
        esc = lambda v: discord.utils.escape_mentions(discord.utils.escape_markdown(str(v)))
        title = esc(raw_title)[:500]
        body = 'HOST GITHUB MERGE CONFIRMATION — human approval required'
        embed = discord.Embed(title='Specific human merge authorization', description=(
            'Risk: GitHub atomically checks the head SHA, but the base branch can be retargeted '
            'between the final check and merge. Approval expires in 10 minutes and permits one attempt. '
            'The administrator must configure this App without protection bypass grants.'))
        for label, value in (
            ('Repository', target['repo']), ('PR number', target['number']),
            ('Base branch', target['base_branch']), ('Head branch', target['head_branch']),
            ('Expected head', target['expected_head_sha']), ('Merge method', target['merge_method']),
            ('Verified PR link', target['url']),
        ):
            value = esc(value)
            if len(value) > 1024:
                return False
            embed.add_field(name=label, value=value, inline=False)
        embed.add_field(name='Untrusted PR-author title', value=title or '(empty)', inline=False)
        if len(embed) > 6000:
            return False
        for user_id in self.approver_ids:
            try:
                user = await client.fetch_user(int(user_id))
                if user.bot:
                    continue
                view = discord.ui.View(timeout=max(0.1, state['deadline'] - time.monotonic()))
                message_binding = {}
                for approve, label, style in [(True, 'Approve this merge', discord.ButtonStyle.danger),
                                               (False, 'Deny', discord.ButtonStyle.secondary)]:
                    button = discord.ui.Button(label=label, style=style, custom_id='github-approval:' + secrets.token_urlsafe(24))
                    async def callback(interaction, decision=approve, binding=message_binding):
                        actor = interaction.user
                        message = getattr(interaction, 'message', None)
                        with self._lock:
                            current = self._requests.get(request_id)
                            valid = (current is state and state['active'] and time.monotonic() < state['deadline']
                                     and not actor.bot and str(actor.id) in self.approver_ids
                                     and str(actor.id) == binding.get('user')
                                     and message is not None and message.id == binding.get('message')
                                     and interaction.channel_id == binding.get('channel')
                                     and getattr(message.author, 'id', None) == client.user.id)
                        if not valid:
                            await interaction.response.send_message('This interaction cannot authorize the request.', ephemeral=True)
                            return
                        on_decision(request_id, str(actor.id), bool(actor.bot), decision)
                        await interaction.response.send_message('Decision recorded for this host request.', ephemeral=True)
                    button.callback = callback
                    view.add_item(button)
                message = await user.send(body, embed=embed, view=view, allowed_mentions=discord.AllowedMentions.none())
                message_binding.update(user=user_id, message=message.id, channel=message.channel.id)
                with self._lock:
                    active = state['active']
                    if active:
                        if not state['presented']:
                            state['deadline'] = time.monotonic() + 600
                            state['presented'] = True
                        view.timeout = max(0.1, state['deadline'] - time.monotonic())
                        state['messages'].append(message)
                        state['views'].append(view)
                if not active:
                    view.stop()
                    await message.edit(content='Host GitHub merge request no longer pending.', view=None)
            except Exception:
                continue
        return state['deadline'] if state['messages'] and state['active'] else False

    def finish(self, request_id, status):
        with self._lock:
            state = self._requests.pop(request_id, None)
            if state is None:
                return
            state['active'] = False
        async def close():
            for view in state['views']:
                view.stop()
            for message in state['messages']:
                try:
                    await message.edit(content='Host GitHub merge request finished: ' + str(status), view=None)
                except Exception:
                    pass
        try:
            asyncio.run_coroutine_threadsafe(close(), state['client'].loop)
        except Exception:
            pass

    def close(self):
        with self._lock:
            ids = list(self._requests)
        for request_id in ids:
            self.finish(request_id, 'cancelled')


def _same_loop(loop):
    try:
        return asyncio.get_running_loop() is loop
    except RuntimeError:
        return False
