FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Node + claude CLI — needed because the retry-with-hint endpoint runs
# a quick Claude turn directly inside the api container. PINNED to >=2.1.156
# (fixes the opus-4-8 thinking-block API 400); the SDK is made to use this
# system CLI via the bundle-removal step after pip install below.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code@2.1.158

COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Remove the SDK's stale bundled `claude` CLI so the transport falls through to
# the npm system CLI pinned above (>=2.1.156). The bundle (SDK 0.2.87 -> CLI
# 2.1.150) still triggers the opus-4-8 thinking-block API 400. The /retry +
# reviewer turns run here too, so the api needs the same fix as the worker.
# memory: sdk_bundled_cli_thinking_400.
RUN find /usr -type f -path "*/claude_agent_sdk/_bundled/claude" -delete 2>/dev/null; \
    echo "SDK bundled CLI removed; system CLI = $(command -v claude) / $(claude --version 2>&1)"

COPY api /app/api

# Same sandbox flag the worker sets so the bundled claude CLI accepts
# --dangerously-skip-permissions even though api runs as root.
ENV IS_SANDBOX=1

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
