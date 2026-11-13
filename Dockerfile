# Dockerfile — پایتون + هسته‌ی Xray (برای Reality / gRPC / HTTPUpgrade)
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# آخرین نسخه‌ی Xray (برای XHTTP+Reality حداقل v24.11 لازمه)
RUN curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip -o /tmp/xray.zip xray -d /usr/local/bin && chmod +x /usr/local/bin/xray && rm /tmp/xray.zip
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# اجرا با uvicorn تا main فقط یک‌بار به اسم "main" ایمپورت بشه (جلوگیری از circular import
# بین main.py و relay_vless.py که با `python main.py` رخ می‌داد)
CMD ["sh", "-c", "uvicorn main:app --no-server-header --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
