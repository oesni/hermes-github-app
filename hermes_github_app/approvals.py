"""Host-owned, single-invocation human merge authorization. Never agent input."""
from __future__ import annotations
import threading
import time
import uuid

CONFIRMATION_SECONDS = 600
TUPLE_FIELDS = ('repo','number','base_branch','head_branch','expected_head_sha','merge_method')

class ApprovalError(Exception):
    def __init__(self,code):
        super().__init__(code)
        self.code=code

class MergeApprovals:
    def __init__(self,adapter,approver_ids,*,clock=time.monotonic):
        self.adapter=adapter
        self.approvers=frozenset(approver_ids)
        self.clock=clock
        self._lock=threading.Lock()
        self._closed=False
        self._pending={}

    def close(self):
        with self._lock:
            self._closed=True
            for record in self._pending.values():
                record['state']='approval_cancelled';record['event'].set()

    def run(self,target,context,recheck,dispatch):
        if self.adapter is None or not self.approvers or context is None or not getattr(context,'identity',None):
            raise ApprovalError('approval_required_unavailable')
        identity=context.identity
        request_id=uuid.uuid4().hex
        record={'state':'pending','event':threading.Event(),'deadline':self.clock()+CONFIRMATION_SECONDS}
        with self._lock:
            if self._closed:raise ApprovalError('approval_cancelled')
            self._pending[request_id]=record
        terminal='approval_required_unavailable'
        def decide(received_id,user_id,is_bot,approve):
            # Only the trusted adapter has this closure. No tool accepts these fields.
            with self._lock:
                if (received_id!=request_id or self._pending.get(request_id) is not record
                    or record['state']!='pending' or self._closed
                    or is_bot is not False or str(user_id) not in self.approvers
                    or type(approve) is not bool or self.clock()>=record['deadline']):return
                record['state']='approved' if approve else 'approval_denied'
                record['event'].set()
        try:
            if context.cancelled():raise ApprovalError('approval_cancelled')
            try:
                presented=self.adapter.present(request_id,dict(target),record['deadline'],decide)
            except Exception:
                raise ApprovalError('approval_required_unavailable') from None
            if not presented:
                raise ApprovalError('approval_required_unavailable')
            with self._lock:
                record['deadline'] = self.clock()+CONFIRMATION_SECONDS if presented is True else float(presented)
            while True:
                with self._lock:
                    if self._closed or context.identity!=identity or context.cancelled():
                        raise ApprovalError('approval_cancelled')
                    if self.clock()>=record['deadline']:raise ApprovalError('approval_expired')
                    state=record['state']
                if state=='approved':break
                if state!='pending':raise ApprovalError(state)
                record['event'].wait(min(.1,max(0,record['deadline']-self.clock())))
            fresh=recheck()
            if any(fresh.get(field)!=target.get(field) for field in TUPLE_FIELDS):
                raise ApprovalError('target_changed')
            with self._lock:
                if self._closed or context.identity!=identity or context.cancelled():raise ApprovalError('approval_cancelled')
                if self.clock()>=record['deadline']:raise ApprovalError('approval_expired')
                if record['state']!='approved':raise ApprovalError('approval_cancelled')
                record['state']='consumed'
            # Exactly this invocation can dispatch; no reusable approval token escapes.
            try:
                result=dispatch()
            except BaseException as exc:
                from .client import ClientError
                if isinstance(exc,ClientError):
                    terminal=exc.code
                    raise
                terminal='uncertain_outcome'
                raise ApprovalError('uncertain_outcome') from None
            terminal='completed'
            return result
        except ApprovalError as exc:
            terminal=exc.code;raise
        except BaseException as exc:
            terminal=getattr(exc,'code','failed');raise
        finally:
            with self._lock:self._pending.pop(request_id,None)
            try:self.adapter.finish(request_id,terminal)
            except Exception:pass
