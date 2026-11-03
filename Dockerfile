FROM node:20-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SAD_SERVE_FRONTEND=1 \
    HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

RUN useradd --create-home --uid 1000 user \
    && mkdir -p /home/user/app/backend/models /home/user/app/var \
    && chown -R user:user /home/user/app
WORKDIR /home/user/app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r backend/requirements.txt

COPY --chown=user:user backend/ ./backend/
COPY --from=frontend-build --chown=user:user /build/frontend/dist ./frontend/dist

WORKDIR /home/user/app/backend
USER user
EXPOSE 7860

# The model is loaded or trained and saved before the API starts. Runtime secrets are
# supplied by the Space environment; no .env file is copied into the image.
CMD ["sh", "-c", "python -c 'from app.model import get_bundle; get_bundle()' && exec uvicorn app.main:app --host 0.0.0.0 --port 7860"]
