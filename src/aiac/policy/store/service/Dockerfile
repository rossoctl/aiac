FROM python:3.12-slim

WORKDIR /app

COPY aiac/policy/store/service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/src
ENV PYTHONPATH=/app/src

# Drop privileges.
RUN useradd --no-create-home --uid 10001 aiac

# Directory for the SQLite backend. Must match the dir of SERVICEPOLICY_DB_PATH's
# default (/data/policy_model.db in aiac.policy.store.service.main); in production this
# is typically a mounted PV, but create it so a default-path start does not fail.
# Owned by the non-root user so a default-path start can write the SQLite file.
RUN mkdir -p /data && chown 10001:10001 /data

USER 10001

CMD ["uvicorn", "aiac.policy.store.service.main:app", "--host", "0.0.0.0", "--port", "7074"]
