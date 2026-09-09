# Build context: aiac/src/
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

WORKDIR /app

# Create the non-root user up front so copied files can be owned by it.
RUN useradd --no-create-home --uid 10001 aiac

COPY --chown=10001:10001 aiac/agent/controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 . /app/src
ENV PYTHONPATH=/app/src

# Drop privileges.
USER 10001

EXPOSE 7070

CMD ["uvicorn", "aiac.agent.controller.routes:app", "--host", "0.0.0.0", "--port", "7070"]
