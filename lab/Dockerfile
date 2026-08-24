FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir flask==3.*
COPY vulnapp/app.py /app/app.py

ENV PORT=8090 ENABLE_GZIP_IN=0
EXPOSE 8090
CMD ["python", "app.py"]
