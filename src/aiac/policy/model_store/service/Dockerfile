FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

WORKDIR /app

# Create the non-root user up front so copied files can be owned by it.
RUN useradd --no-create-home --uid 10001 aiac

COPY --chown=10001:10001 aiac/policy/model_store/service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 . /app/src
ENV PYTHONPATH=/app/src

# Drop privileges.

# Directory for the SQLite backend. Must match the dir of SERVICEPOLICY_DB_PATH's
# default (/data/policy_model.db in aiac.policy.model_store.service.main); in production this
# is typically a mounted PV, but create it so a default-path start does not fail.
# Owned by the non-root user so a default-path start can write the SQLite file.
RUN mkdir -p /data && chown 10001:10001 /data

USER 10001

CMD ["uvicorn", "aiac.policy.model_store.service.main:app", "--host", "0.0.0.0", "--port", "7074"]
