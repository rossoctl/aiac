# Build context: aiac/src/
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

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
