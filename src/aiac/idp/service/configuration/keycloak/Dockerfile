FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Drop privileges.
RUN useradd --no-create-home --uid 10001 aiac
USER 10001

EXPOSE 7071

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7071"]
