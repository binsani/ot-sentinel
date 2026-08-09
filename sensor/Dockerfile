FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /sensor
RUN addgroup --system otsentinel && adduser --system --ingroup otsentinel otsentinel
COPY pyproject.toml ./
COPY uv.lock ./
COPY src ./src
RUN pip install --no-cache-dir uv==0.12.3 \
    && uv sync --frozen --no-cache \
    && mkdir -p /var/lib/ot-sentinel/incoming /var/lib/ot-sentinel/archive \
    && chown -R otsentinel:otsentinel /var/lib/ot-sentinel
USER otsentinel
ENV PATH="/sensor/.venv/bin:$PATH"
ENTRYPOINT ["ot-sentinel-sensor"]
CMD ["--help"]
