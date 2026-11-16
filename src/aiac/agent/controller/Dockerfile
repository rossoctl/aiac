# Build context: aiac/src/
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
