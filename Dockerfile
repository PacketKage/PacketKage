# ---- Stage 1: build the frontend ----
FROM node:22-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# vite builds with relative asset paths for embedding in the backend
RUN npm run build

# ---- Stage 2: backend + built frontend ----
FROM python:3.12-slim AS runtime
# libpcap for live-capture support (scapy); tshark optional but handy
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/pyproject.toml backend/mypy.ini ./
COPY --from=frontend-build /build/dist ./app/dist

# persistent analysis data (SQLite DB + uploads)
ENV PACKETKAGE_DB=sqlite:////data/packetkage.db \
    PACKETKAGE_UPLOAD_DIR=/data/uploads
VOLUME ["/data"]
RUN mkdir -p /data/uploads

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
