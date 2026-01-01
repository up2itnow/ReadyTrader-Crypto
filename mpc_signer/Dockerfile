FROM public.ecr.aws/docker/library/golang:1.24.6-bookworm

LABEL description="ReadyTrader-Crypto MPC signer (Coinbase cb-mpc) build + runtime"

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local \
    GOFLAGS=-buildvcs=false \
    BUILD_TYPE=Release \
    CC=/usr/bin/clang-20 \
    CXX=/usr/bin/clang++-20

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    rsync \
    wget \
    gnupg \
    ca-certificates \
    lsb-release \
    openssl \
    && rm -rf /var/lib/apt/lists/* \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-20 main" > /etc/apt/sources.list.d/llvm20.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    clang-20 \
    clang-format-20 \
    lld-20 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code
COPY . /code

# Build custom OpenSSL + cb-mpc C++ library + the MPC signer binary
RUN cd /code/vendor/cb-mpc \
    && make openssl-linux \
    && make build-no-test BUILD_TYPE=${BUILD_TYPE} \
    && cd /code/mpc_signer \
    && export CGO_CFLAGS="-I/code/vendor/cb-mpc/src" \
    && export CGO_CXXFLAGS="-I/code/vendor/cb-mpc/src" \
    && export CGO_LDFLAGS="-L/code/vendor/cb-mpc/lib/${BUILD_TYPE}" \
    && go mod tidy \
    && go build -o /usr/local/bin/mpc-signer .

EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/mpc-signer"]

