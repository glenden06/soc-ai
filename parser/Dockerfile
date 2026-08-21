FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY parser/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ /app/common/
COPY parser/ /app/parser/

RUN useradd --create-home --shell /usr/sbin/nologin socai && chown -R socai:socai /app
USER socai

WORKDIR /app/parser
CMD ["python", "parser.py"]
