FROM gcc:13
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends make && rm -rf /var/lib/apt/lists/*
COPY Makefile /app/Makefile
COPY main.cpp /app/main.cpp
CMD ["sh", "-lc", "make OUT_DIR=/outputs && /outputs/basiccpp"]
