FROM python:3.12-slim

LABEL maintainer="agentverif.com"
LABEL description="agentverif-sign — SCAN → SIGN → VERIFY for AI agents"

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir ".[crypto]"

ENTRYPOINT ["agentverif-sign"]
CMD ["--help"]
