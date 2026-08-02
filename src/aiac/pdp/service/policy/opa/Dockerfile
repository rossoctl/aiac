FROM python:3.12-slim

WORKDIR /app

COPY aiac/pdp/service/policy/opa/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/src
ENV PYTHONPATH=/app/src

# Drop privileges.
RUN useradd --no-create-home --uid 10001 aiac
USER 10001

EXPOSE 7072

CMD ["uvicorn", "aiac.pdp.service.policy.opa.main:app", "--host", "0.0.0.0", "--port", "7072"]
