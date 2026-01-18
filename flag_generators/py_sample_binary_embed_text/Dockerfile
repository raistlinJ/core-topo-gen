FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
	&& apt-get install -y --no-install-recommends gcc libc6-dev binutils \
	&& rm -rf /var/lib/apt/lists/*
COPY generator.py /app/generator.py
CMD ["python", "generator.py", "--config", "/inputs/config.json", "--out-dir", "/outputs"]
