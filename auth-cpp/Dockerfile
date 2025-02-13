FROM ghcr.io/userver-framework/ubuntu-22.04-userver-pg:latest
RUN apt update
RUN apt upgrade -y
RUN apt install -y build-essential cmake tar wget curl zip git pkg-config ninja-build
RUN apt install -y gdb mold clangd
WORKDIR /app
COPY src/ src/
COPY CMakeLists.txt CMakeLists.txt
COPY testsuite/ testsuite/
RUN mkdir -p third_party && git clone https://github.com/arun11299/cpp-jwt.git third_party/cpp-jwt
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DUSERVER_INSTALL=ON -DUSERVER_FEATURE_EASY=ON -DUSERVER_FEATURE_POSTGRESQL=ON && \
    cmake --build build -j$(nproc)
