"""Optional OpenTelemetry support.

The engine records a token-exchange counter and span. OpenTelemetry is an
optional dependency: when ``opentelemetry-api`` is not installed (or fails to
import) no-op shims are used so the library stays usable in apps that don't run
OpenTelemetry. Install the ``otel`` extra to enable it.
"""

try:
    from opentelemetry import trace
    from opentelemetry.metrics import get_meter

    tracer = trace.get_tracer("dbd.oidc_client")
    meter = get_meter("dbd.oidc_client")

except Exception:  # pragma: no cover - exercised only when OTel is absent

    class _NoopSpan:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _NoopTracer:
        def start_as_current_span(self, *args, **kwargs):
            return _NoopSpan()

    class _NoopCounter:
        def add(self, *args, **kwargs):
            return None

    class _NoopMeter:
        def create_counter(self, *args, **kwargs):
            return _NoopCounter()

    tracer = _NoopTracer()
    meter = _NoopMeter()
