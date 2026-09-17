# syntax=docker/dockerfile:1

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Install the project as a package so both the UI and `satsa` CLI are available.
COPY pyproject.toml requirements.txt README.md ./
COPY sat_sa ./sat_sa
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/runs \
    && chown -R appuser:appuser /app

COPY detector_config.yaml app.py ./
RUN chown appuser:appuser /app/detector_config.yaml /app/app.py

USER appuser

EXPOSE 8501

VOLUME ["/app/runs"]

ENTRYPOINT ["streamlit", "run", "app.py"]
