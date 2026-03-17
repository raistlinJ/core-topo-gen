FROM python:3.10-slim

WORKDIR /app
COPY . /app

ENV PIP_PREFER_BINARY=1
ENV PYTHONPATH=/app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential python3-dev graphviz \
	&& rm -rf /var/lib/apt/lists/*

# Install runtime dependencies for the web app
RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 9090
CMD ["python", "-m", "webapp.app_backend"]
