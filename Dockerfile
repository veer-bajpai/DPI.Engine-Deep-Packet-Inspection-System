FROM python:3.11-slim

RUN apt-get update && apt-get install -y cmake g++ make && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build build --parallel \
    && cp build/dpi_engine ./dpi_engine

RUN pip install --no-cache-dir fastapi uvicorn python-multipart

EXPOSE 10000
CMD ["sh", "-c", "uvicorn web.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
