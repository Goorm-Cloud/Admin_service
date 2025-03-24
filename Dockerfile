#FROM python:3.10
#
#WORKDIR /app
#
## Install system dependencies
#RUN apt-get update && apt-get install -y \
#    gcc \
#    && rm -rf /var/lib/apt/lists/*
#
## Copy requirements first for better cache
#COPY requirements.txt .
#RUN pip install --no-cache-dir -r requirements.txt
#
## Copy the rest of the application
#COPY . .
#
## Set environment variables
#ENV FLASK_APP=app.py
#ENV FLASK_ENV=production
#ENV PYTHONUNBUFFERED=1
#
## Expose port
#EXPOSE 8001

FROM python:3.10

# 작업 디렉토리 설정
WORKDIR /app

# 최신 pip 설치
RUN pip install --upgrade pip

# 애플리케이션 코드 복사
COPY . .

# Jenkins에서 생성한 config.py 및 .env 파일을 컨테이너에 포함
# (Jenkins 파이프라인에서 config.py와 .env를 빌드 단계에서 생성하므로 Dockerfile에서는 별도로 복사하지 않음)

# 패키지 설치
RUN pip install -r requirements.txt

# Flask 관련 환경변수 설정
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8001", "--workers", "4", "--log-level=debug", "--access-logfile=-", "--error-logfile=-", "--timeout", "300", "app:app"]