FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY llm_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ /app/common/
COPY llm_agent/ /app/llm_agent/

RUN useradd --create-home --shell /usr/sbin/nologin socai && chown -R socai:socai /app
USER socai

WORKDIR /app/llm_agent
CMD ["python", "agent.py"]
