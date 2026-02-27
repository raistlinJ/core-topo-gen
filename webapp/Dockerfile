FROM python:3.10-slim

WORKDIR /app
COPY . /app

ENV PIP_PREFER_BINARY=1

# Install runtime dependencies for the web app
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 9090
CMD ["python", "webapp/app_backend.py"]
