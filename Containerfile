# Exact reviewed CPython image; dependency wheels/sdists pinned by uv.lock.
FROM python@sha256:fbecd461fc72d21b2143c6eaba25143738079154a6d0ea3da3aec724f50eed4a AS asu_build
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY asu ./asu
RUN python -m pip install --no-cache-dir uv==0.9.12 && \
    uv sync --frozen --no-dev --no-editable

FROM python@sha256:fbecd461fc72d21b2143c6eaba25143738079154a6d0ea3da3aec724f50eed4a
WORKDIR /app
COPY --from=asu_build /app/.venv /app/.venv
COPY ops/immutable_mirror.py ops/promote.py ops/builder_image.py /app/ops/
COPY ops/hosted_context.py ops/hosted_inspection.py ops/native_acceptance.py /app/ops/
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
USER 1000:1000
CMD ["uvicorn", "asu.main:app", "--host", "0.0.0.0", "--port", "8000"]
