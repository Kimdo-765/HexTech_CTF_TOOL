"""Production routing and usage adapters for the live-fire patch loop.

The live-fire state machine deliberately owns no provider clients.  Instead an
``AgentInvoker`` receives a resolved call and adapts Claude, GPT, or Grok to the
small synchronous boundaries in :mod:`modules.live_fire_patch_loop`.  Keeping
the transport injectable lets the LF-4 gate exercise the real routing and
ledger without making an LLM call.

Routing is not reimplemented here:

* ``main`` always uses the job's whole-job provider.
* ``reviewer`` and ``report`` use the create-time role snapshot.
* model selection uses the routed provider's existing role preset contract.

The existing ``agent_provider.enrich_job_meta`` remains the only create-time
snapshot writer.  This module only reads the resulting job metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from modules import agent_provider, usage_ledger
from modules.live_fire_patch_loop import (
    PatchLoopSpec,
    PatchRunResult,
    ProviderResult,
    ReportContext,
    ReviewContext,
    ReviewResult,
    run_patch_loop,
)


LIVE_FIRE_ROLES = frozenset({"main", "reviewer", "report"})
ROLE_STAGES = {
    "main": "patch",
    "reviewer": "review",
    "report": "report",
}


class LiveFireProviderError(RuntimeError):
    """The injected provider adapter violated the live-fire boundary."""


@dataclass(frozen=True)
class AgentRoute:
    """A provider/model decision resolved from one job snapshot."""

    role: str
    provider: str
    model: str


@dataclass(frozen=True)
class AgentUsage:
    """Provider-neutral accounting returned by one adapter invocation."""

    model: str | None = None
    tokens: Mapping[str, int] = field(default_factory=dict)
    cost_usd: float | None = None
    cost_basis: str = "none"
    runtime: str | None = None
    window: Mapping[str, Any] = field(default_factory=dict)
    error_kind: str | None = None


@dataclass(frozen=True)
class AgentInvocationResult:
    """Typed value plus the usage emitted while producing it."""

    value: Any
    usage: AgentUsage = field(default_factory=AgentUsage)


@dataclass(frozen=True)
class AgentCall:
    """One routed live-fire provider call."""

    job_id: str
    route: AgentRoute
    stage: str
    attempt: int
    payload: Any


class AgentInvoker(Protocol):
    def invoke(self, call: AgentCall) -> AgentInvocationResult:
        """Run one already-routed call and return value plus usage."""


def _provider_for_role(job_id: str, role: str) -> str:
    if role == "main":
        return agent_provider.provider_for_job(job_id)
    return agent_provider.provider_for_role(job_id, role)


def resolve_live_fire_route(
    job_id: str,
    role: str,
    requested_model: str | None = None,
) -> AgentRoute:
    """Resolve one live-fire role through the production job snapshot."""

    normalized_role = str(role or "").strip().lower()
    if normalized_role not in LIVE_FIRE_ROLES:
        raise LiveFireProviderError(f"unsupported live-fire role: {role!r}")
    provider = _provider_for_role(job_id, normalized_role)
    model = agent_provider.role_model_for(
        normalized_role,
        provider,
        requested_model,
    )
    return AgentRoute(
        role=normalized_role,
        provider=provider,
        model=model,
    )


def resolve_live_fire_routes(
    job_id: str,
    requested_models: Mapping[str, str | None] | None = None,
) -> dict[str, AgentRoute]:
    """Resolve the main/reviewer/report triplet for inspection or launch."""

    models = requested_models or {}
    return {
        role: resolve_live_fire_route(job_id, role, models.get(role))
        for role in ("main", "reviewer", "report")
    }


def _record_call_usage(
    call: AgentCall,
    result: AgentInvocationResult,
) -> dict[str, Any] | None:
    """Write one provider×model×role×stage×attempt ledger row.

    ``usage_ledger.record_usage`` owns the direct ``attempt`` dimension and
    allocates it under its cross-process lock.  ``live_fire_attempt`` preserves
    which patch-loop attempt led to a reviewer/report call without replacing
    that canonical invocation counter.
    """

    usage = result.usage
    runtime = usage.runtime
    if runtime is None and call.route.provider == "gpt":
        runtime = agent_provider.get_gpt_runtime()
    return usage_ledger.record_usage(
        call.job_id,
        role=call.route.role,
        stage=call.stage,
        provider=call.route.provider,
        model=usage.model or call.route.model,
        tokens=dict(usage.tokens),
        cost_usd=usage.cost_usd,
        cost_basis=usage.cost_basis,
        runtime=runtime,
        window=dict(usage.window),
        error_kind=usage.error_kind,
        extra={"live_fire_attempt": call.attempt},
    )


class _RoutedRole:
    def __init__(
        self,
        job_id: str,
        invoker: AgentInvoker,
        role: str,
        requested_model: str | None = None,
    ) -> None:
        self.job_id = str(job_id)
        self.invoker = invoker
        self.role = role
        self.requested_model = requested_model

    def _invoke(self, payload: Any, attempt: int) -> AgentInvocationResult:
        route = resolve_live_fire_route(
            self.job_id,
            self.role,
            self.requested_model,
        )
        call = AgentCall(
            job_id=self.job_id,
            route=route,
            stage=ROLE_STAGES[self.role],
            attempt=attempt,
            payload=payload,
        )
        result = self.invoker.invoke(call)
        if not isinstance(result, AgentInvocationResult):
            raise LiveFireProviderError(
                f"{self.role} invoker returned {type(result).__name__}, "
                "expected AgentInvocationResult"
            )
        _record_call_usage(call, result)
        return result


class RoutedPatchProvider(_RoutedRole):
    def __init__(
        self,
        job_id: str,
        invoker: AgentInvoker,
        requested_model: str | None = None,
    ) -> None:
        super().__init__(job_id, invoker, "main", requested_model)

    def attempt(self, context) -> ProviderResult:
        value = self._invoke(context, context.attempt).value
        if not isinstance(value, ProviderResult):
            raise LiveFireProviderError("main invoker did not return ProviderResult")
        return value


class RoutedPatchReviewer(_RoutedRole):
    def __init__(
        self,
        job_id: str,
        invoker: AgentInvoker,
        requested_model: str | None = None,
    ) -> None:
        super().__init__(job_id, invoker, "reviewer", requested_model)

    def review(self, context: ReviewContext) -> ReviewResult:
        value = self._invoke(context, context.attempt).value
        if not isinstance(value, ReviewResult):
            raise LiveFireProviderError("reviewer invoker did not return ReviewResult")
        return value


class RoutedPatchReporter(_RoutedRole):
    def __init__(
        self,
        job_id: str,
        invoker: AgentInvoker,
        requested_model: str | None = None,
    ) -> None:
        super().__init__(job_id, invoker, "report", requested_model)

    def report(self, context: ReportContext) -> str:
        patch_attempt = max(1, int(context.document.get("attempts") or 0))
        value = self._invoke(context, patch_attempt).value
        if not isinstance(value, str):
            raise LiveFireProviderError("report invoker did not return text")
        return value


def run_routed_patch_loop(
    job_id: str,
    workspace,
    output_dir,
    spec: PatchLoopSpec,
    invoker: AgentInvoker,
    *,
    requested_models: Mapping[str, str | None] | None = None,
    runtime_factory=None,
    clock=None,
) -> PatchRunResult:
    """Run LF-3 through snapshotted main/reviewer/report routes."""

    models = requested_models or {}
    provider = RoutedPatchProvider(job_id, invoker, models.get("main"))
    reviewer = RoutedPatchReviewer(job_id, invoker, models.get("reviewer"))
    reporter = RoutedPatchReporter(job_id, invoker, models.get("report"))
    return run_patch_loop(
        workspace,
        output_dir,
        spec,
        provider,
        reviewer,
        reporter=reporter,
        runtime_factory=runtime_factory,
        clock=clock,
    )


__all__ = [
    "AgentCall",
    "AgentInvocationResult",
    "AgentInvoker",
    "AgentRoute",
    "AgentUsage",
    "LIVE_FIRE_ROLES",
    "LiveFireProviderError",
    "RoutedPatchProvider",
    "RoutedPatchReporter",
    "RoutedPatchReviewer",
    "resolve_live_fire_route",
    "resolve_live_fire_routes",
    "run_routed_patch_loop",
]
