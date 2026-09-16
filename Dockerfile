# ---- Stage 1: build the frontend ----
FROM node:24-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# vite builds with relative asset paths for embedding in the backend
RUN npm run build

# ---- Stage 2: backend + built frontend ----
FROM python:3.12-slim AS runtime
# libpcap for live-capture support (scapy); libcap2-bin provides setcap
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/pyproject.toml backend/mypy.ini ./
COPY --from=frontend-build /build/dist ./app/dist

# --- non-root runtime user + least-privilege live-capture capabilities ---
# Live sniffing needs CAP_NET_RAW (AF_PACKET socket) + CAP_NET_ADMIN (bind).
# File capabilities on the interpreter deliver them to the NON-ROOT process
# (cap_add alone only equips root), matching the native-Linux setup in the
# README. The container still needs cap_add in compose to keep the bounding
# set from masking these (NET_ADMIN is not in the runtime default set).
RUN useradd --uid 1000 --create-home packetkage \
    && setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/python3.12 \
    && chown -R packetkage:packetkage /srv

# persistent analysis data (SQLite DB + uploads)
ENV PACKETKAGE_DB=sqlite:////data/packetkage.db \
    PACKETKAGE_UPLOAD_DIR=/data/uploads
VOLUME ["/data"]
RUN mkdir -p /data/uploads && chown -R packetkage:packetkage /data

USER packetkage
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
