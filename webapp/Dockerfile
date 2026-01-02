FROM python:3.10-slim

WORKDIR /app
COPY . /app

# psutil is pinned and may require a compiler on some platforms (e.g. arm64).
RUN apt-get update \
	&& apt-get install -y --no-install-recommends gcc python3-dev \
	&& rm -rf /var/lib/apt/lists/*

# Install runtime dependencies for the web app
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 9090
CMD ["python", "webapp/app_backend.py"]
