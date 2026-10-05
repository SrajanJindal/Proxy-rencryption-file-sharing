FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential libffi-dev python3-dev

RUN pip install umbral fastapi uvicorn pydantic

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
