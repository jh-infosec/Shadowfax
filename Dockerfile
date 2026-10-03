# Shadowfax, as one image (v0.12).
#
# Two stages. The first builds the dashboard with Node; the second runs the API
# with Python and serves the built dashboard from its own origin. Node does not
# survive into the final image -- a build tool in a running security container
# is attack surface that earns nothing.
#
# One process on one port is the point. It removes the two things that make a
# "just try it" fail: a second server to start, and a CORS allowlist that has to
# match whatever port the dashboard ended up on.

# ---- stage 1: build the dashboard ----------------------------------------
FROM node:20-alpine AS dashboard

WORKDIR /build

# Dependencies first, so editing a component does not re-resolve the tree.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./

# Empty, not unset: the dashboard is served by the API itself here, so every
# request goes to the page's own origin. `api.js` reads this with `??` so an
# explicit empty string survives as an answer rather than falling back.
ENV VITE_API_BASE=""
RUN npm run build


# ---- stage 2: the runtime -------------------------------------------------
FROM python:3.11-slim AS runtime

# Unbuffered so `docker compose up` shows the log as it happens rather than in
# chunks when a buffer happens to fill.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SHADOWFAX_DB=/data/shadowfax.db

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py attack_registry.json ./
COPY --from=dashboard /build/dist ./frontend/dist

# The database lives on a volume, so `docker compose down` does not throw away
# an investigation and `docker compose down -v` deliberately does.
RUN mkdir -p /data

# A non-root user, because a tool that spends its time telling you about
# privilege escalation should not be running as root to say it.
RUN useradd --system --uid 10001 --home /app shadowfax \
    && chown -R shadowfax:shadowfax /app /data
USER shadowfax

EXPOSE 8000

# Reports unhealthy while the API is not answering, so `docker compose up
# --wait` and any orchestrator can tell "starting" from "broken".
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
