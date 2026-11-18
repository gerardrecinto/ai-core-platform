FROM python:3.12-slim
RUN useradd --system --uid 10001 aicore
WORKDIR /app
COPY src/ src/
ENV PYTHONPATH=/app/src HOST=0.0.0.0 PORT=8080 PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8080
CMD ["python", "-m", "aicore.server"]
