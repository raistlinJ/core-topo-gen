FROM python:3.11-slim
WORKDIR /app
COPY generator.py /app/generator.py
CMD ["python", "generator.py", "--config", "/inputs/config.json", "--base-dir", "/outputs"]
