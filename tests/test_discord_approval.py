"""Real discord.py UI objects with a mocked network and live asyncio loop."""
import asyncio
import concurrent.futures
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from hermes_github_app.discord_approval import DiscordApprovalAdapter, active_discord_client

TARGET = {
    'repo': 'acme/demo', 'number': 3, 'base_branch': 'main',
    'head_branch': 'feature', 'expected_head_sha': 'a' * 40,
    'merge_method': 'squash', 'url': 'https://github.com/acme/demo/pull/3',
    'title': '**unsafe** @everyone',
}


@pytest.fixture
def live_client():
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    def run():
        asyncio.set_event_loop(loop)
        ready.set()
        loop.run_forever()
    thread = threading.Thread(target=run)
    thread.start()
    assert ready.wait(2)
    client = SimpleNamespace(loop=loop, user=SimpleNamespace(id=999), sent=[])
    async def fetch_user(user_id):
        async def send(body, **kwargs):
            message = SimpleNamespace(id=1000 + len(client.sent), channel=SimpleNamespace(id=7),
                author=client.user, edit=AsyncMock())
            client.sent.append((user_id, body, kwargs, message))
            return message
        return SimpleNamespace(id=user_id, bot=False, send=send)
    client.fetch_user = fetch_user
    yield client
    async def drain():
        await asyncio.sleep(0)
        tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run_coroutine_threadsafe(drain(), loop).result(2)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(2)
    loop.close()


def interaction(client, **changes):
    message = client.sent[0][3]
    values = {'user': SimpleNamespace(id=123, bot=False), 'message': message,
        'channel_id': message.channel.id, 'response': SimpleNamespace(send_message=AsyncMock())}
    values.update(changes)
    return SimpleNamespace(**values)


def click(client, ui, button=0):
    view = client.sent[0][2]['view']
    asyncio.run_coroutine_threadsafe(view.children[button].callback(ui), client.loop).result(2)


def test_actual_view_human_confirmation_and_untrusted_text(live_client):
    decisions = Mock()
    adapter = DiscordApprovalAdapter(['123'], lambda: live_client)
    before = time.monotonic()
    deadline = adapter.present('host-call', TARGET, before + 600, decisions)
    assert before + 599 < deadline <= time.monotonic() + 600
    _, body, kwargs, message = live_client.sent[0]
    assert 'HOST GITHUB MERGE CONFIRMATION' in body
    embed = kwargs['embed']
    title_field = next(field for field in embed.fields if field.name == 'Untrusted PR-author title')
    assert '\\*\\*unsafe\\*\\*' in title_field.value
    assert '@everyone' not in title_field.value
    assert 'base branch can be retargeted' in embed.description
    assert kwargs['allowed_mentions'].everyone is False
    assert len(kwargs['view'].children) == 2
    assert kwargs['view'].children[0].custom_id != kwargs['view'].children[1].custom_id
    click(live_client, interaction(live_client))
    decisions.assert_called_once_with('host-call', '123', False, True)
    adapter.finish('host-call', 'completed')
    asyncio.run_coroutine_threadsafe(asyncio.sleep(.01), live_client.loop).result(2)
    message.edit.assert_awaited_once()


@pytest.mark.parametrize('invalid', ['bot', 'unlisted', 'other_approver', 'message', 'channel', 'author', 'expired', 'finished'])
def test_invalid_interactions_cannot_authorize(live_client, invalid):
    decisions = Mock()
    adapter = DiscordApprovalAdapter(['123'], lambda: live_client)
    assert adapter.present('host-call', TARGET, time.monotonic() + 600, decisions)
    ui = interaction(live_client)
    if invalid == 'bot': ui.user.bot = True
    if invalid == 'unlisted': ui.user.id = 321
    if invalid == 'other_approver':
        adapter.approver_ids = frozenset({'123', '321'})
        ui.user.id = 321
    if invalid == 'message':
        ui.message = SimpleNamespace(id=999999, author=live_client.user)
    if invalid == 'channel': ui.channel_id = 999999
    if invalid == 'author':
        ui.message = SimpleNamespace(id=ui.message.id, author=SimpleNamespace(id=888))
    if invalid == 'expired': adapter._requests['host-call']['deadline'] = time.monotonic() - 1
    if invalid == 'finished': adapter.finish('host-call', 'cancelled')
    click(live_client, ui)
    decisions.assert_not_called()
    assert 'cannot authorize' in ui.response.send_message.call_args.args[0]
    adapter.close()


def test_deny_is_authenticated_and_bot_recipient_not_contacted(live_client):
    decisions = Mock()
    adapter = DiscordApprovalAdapter(['123'], lambda: live_client)
    assert adapter.present('host-call', TARGET, time.monotonic() + 600, decisions)
    click(live_client, interaction(live_client), button=1)
    decisions.assert_called_once_with('host-call', '123', False, False)
    adapter.close()
    live_client.fetch_user = AsyncMock(return_value=SimpleNamespace(bot=True))
    assert adapter.present('other-call', TARGET, time.monotonic() + 600, decisions) is False
    assert len(live_client.sent) == 1
    adapter.close()


def test_present_timeout_cancels_future_and_stale_view_cannot_approve(live_client, monkeypatch):
    entered = threading.Event()
    original_fetch = live_client.fetch_user
    async def fetch_user(user_id):
        user = await original_fetch(user_id)
        original_send = user.send
        async def send(body, **kwargs):
            message = await original_send(body, **kwargs)
            entered.set()
            await asyncio.sleep(100)
            return message
        user.send = send
        return user
    live_client.fetch_user = fetch_user
    original_schedule = asyncio.run_coroutine_threadsafe
    futures = []
    class TimedOutFuture:
        def __init__(self, future): self.future = future
        def result(self, timeout):
            assert entered.wait(2)
            raise concurrent.futures.TimeoutError()
        def cancel(self): return self.future.cancel()
    def schedule(coroutine, loop):
        future = original_schedule(coroutine, loop)
        futures.append(future)
        return TimedOutFuture(future) if len(futures) == 1 else future
    decisions = Mock()
    adapter = DiscordApprovalAdapter(['123'], lambda: live_client)
    with monkeypatch.context() as patch:
        patch.setattr(asyncio, 'run_coroutine_threadsafe', schedule)
        assert adapter.present('host-call', TARGET, time.monotonic() + 600, decisions) is False
    assert futures[0].cancelled()
    click(live_client, interaction(live_client))
    decisions.assert_not_called()
    assert not adapter._requests


def test_gateway_lookup_named_single_profile_and_multiplex_refusal(monkeypatch):
    client = SimpleNamespace(is_ready=lambda: True, is_closed=lambda: False)
    runner = SimpleNamespace(config=SimpleNamespace(multiplex_profiles=False),
        adapters={'discord': SimpleNamespace(_client=client)},
        profile_adapters={'named-profile': {'discord': SimpleNamespace(_client=object())}})
    run_module = ModuleType('gateway.run')
    run_module._gateway_runner_ref = lambda: runner
    config_module = ModuleType('gateway.config')
    config_module.Platform = SimpleNamespace(DISCORD='discord')
    monkeypatch.setitem(sys.modules, 'gateway.run', run_module)
    monkeypatch.setitem(sys.modules, 'gateway.config', config_module)
    assert active_discord_client() is client
    runner.config.multiplex_profiles = True
    assert active_discord_client() is None


def test_same_loop_is_refused_without_deadlock(live_client):
    adapter = DiscordApprovalAdapter(['123'], lambda: live_client)
    async def call():
        return adapter.present('host-call', TARGET, time.monotonic() + 600, Mock())
    assert asyncio.run_coroutine_threadsafe(call(), live_client.loop).result(2) is False
    assert not live_client.sent


def test_maximum_confirmation_uses_bounded_embed_and_single_line_title(live_client):
    target={**TARGET,'repo':'a'*39+'/'+'b'*100,'head_branch':'_'*255,'base_branch':'_'*255,
        'title':'unsafe\nBASE: spoof\r\t\u202e\u2066@everyone'+'*'*500}
    adapter=DiscordApprovalAdapter(['123'],lambda:live_client)
    assert adapter.available() is True
    assert adapter.present('host-call',target,time.monotonic()+600,Mock())
    _,content,kwargs,_=live_client.sent[0]
    embed=kwargs['embed']
    assert len(content)<=2000 and len(embed)<=6000
    assert all(len(field.value)<=1024 for field in embed.fields)
    title=next(field.value for field in embed.fields if field.name=='Untrusted PR-author title')
    assert all(character not in title for character in ('\n','\r','\t','\u202e','\u2066','@everyone'))
    assert 'base branch can be retargeted' in embed.description
    assert next(field.value for field in embed.fields if field.name=='Expected head')==target['expected_head_sha']
    adapter.close()


def test_disconnected_adapter_not_available():
    assert DiscordApprovalAdapter(['123'],lambda:None).available() is False
