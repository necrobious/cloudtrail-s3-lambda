FROM amazonlinux:latest 

ARG SRC

ENV BUILD_DIR=/build \
    OUTPUT_DIR=/output \
    RUST_BACKTRACE=1 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    PREFIX=/musl \
    MUSL_VERSION=1.1.20 \
    OPENSSL_VERSION=1.1.0j


RUN curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain stable -y

ENV BUILD_TARGET=x86_64-unknown-linux-musl

RUN rustup target add $BUILD_TARGET

RUN yum -y groupinstall "Development Tools"

WORKDIR $PREFIX

# Build any dependencies that aren't part of your build, e.g. thrift compiler

ADD keys.gpg .
RUN gpg --import keys.gpg

# Build Musl
ADD https://www.musl-libc.org/releases/musl-$MUSL_VERSION.tar.gz .
ADD https://www.musl-libc.org/releases/musl-$MUSL_VERSION.tar.gz.asc .
RUN [[ "`gpg --verify musl-$MUSL_VERSION.tar.gz.asc musl-$MUSL_VERSION.tar.gz 2>&1`" == *"Good signature from"*"musl libc <musl@libc.org>"* ]]
RUN tar -xvzf musl-$MUSL_VERSION.tar.gz \
    && cd musl-$MUSL_VERSION \
    && ./configure --prefix=$PREFIX \
    && make install \
    && cd ..

# Set environment for musl
ENV CC=$PREFIX/bin/musl-gcc \
    C_INCLUDE_PATH=$PREFIX/include/ \
    CPPFLAGS=-I$PREFIX/include \
    LDFLAGS=-L$PREFIX/lib

# Build OpenSSL
ADD https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz .
ADD https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz.asc .
RUN [[ "`gpg --verify openssl-$OPENSSL_VERSION.tar.gz.asc openssl-$OPENSSL_VERSION.tar.gz 2>&1`" == *"Good signature from"*"Matt Caswell <matt@openssl.org>"* ]]
RUN echo "Building OpenSSL" \
    && tar -xzf "openssl-$OPENSSL_VERSION.tar.gz" \
    && cd openssl-$OPENSSL_VERSION \
    && ./Configure no-async no-afalgeng no-shared no-zlib -fPIC --prefix=$PREFIX --openssldir=$PREFIX/ssl linux-x86_64 \
    && make depend \
    && make install

WORKDIR $BUILD_DIR

ENV OPENSSL_DIR=$PREFIX \
    OPENSSL_STATIC=true

#FROM rust_aws_lambda_build:latest

ENV OUTPUT_DIR=/output \
    ARTIFACTS_DIR=/artifacts \
    EXPORT_DIR=/export

RUN yum -y install zip

# docker + cargo cache workaround. do a fake-build to pull and cache the dependencies
# in the docker image. Then move source directory in and commit the second (actual)
# codebuild.
ADD $SRC/Cargo.toml $SRC/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --target $BUILD_TARGET
RUN cargo build --target $BUILD_TARGET --release
RUN rm src/main.rs
ADD $SRC/src src
RUN cargo test  --target $BUILD_TARGET -- --nocapture
RUN cargo build --target $BUILD_TARGET --release

RUN mkdir ${OUTPUT_DIR}
RUN find target/${BUILD_TARGET}/release -maxdepth 1 -type f -executable -exec cp '{}' ${OUTPUT_DIR} \;
RUN mkdir -p ${ARTIFACTS_DIR}
RUN cp -r ${OUTPUT_DIR}/* ${ARTIFACTS_DIR}

WORKDIR $ARTIFACTS_DIR

RUN find . -maxdepth 1 -type f -executable -exec zip aws_lambda.zip '{}' \;

RUN ls -a $ARTIFACTS_DIR

RUN mkdir -p $EXPORT_DIR

#Snapshot the directory
VOLUME $EXPORT_DIR

CMD find $ARTIFACTS_DIR -type f -name "aws_lambda.zip" -exec cp '{}' $EXPORT_DIR \;
