# Global build args
ARG APP_DIR="/var/task"
ARG PYTHON_VERSION="3.8"
ARG ALPINE_VERSION="3.12"

# Build base image
FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS python-alpine
RUN apk add libstdc++

# Install AWS Lambda runtime
FROM python-alpine AS build-image
RUN apk add \
    build-base \
    libtool \
    autoconf \
    automake \
    libexecinfo-dev \
    make \
    cmake \
    libcurl \
    gcc \
    g++ \
    musl-dev \
    python3-dev \
    linux-headers \
    libffi-dev \
    openssl-dev

ARG APP_DIR
RUN mkdir -pv ${APP_DIR}
RUN python -m pip install awslambdaric --target ${APP_DIR}/site-packages
COPY . ${APP_DIR}
RUN python -m pip install ${APP_DIR}/ --target ${APP_DIR}/site-packages -r ${APP_DIR}/requirements.txt

# Final runtime image
FROM python-alpine
ARG APP_DIR
ENV PYTHONPATH=${APP_DIR}:${APP_DIR}/site-packages
WORKDIR ${APP_DIR}/site-packages
COPY --from=build-image ${APP_DIR} ${APP_DIR}
ADD https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie /usr/bin/aws-lambda-rie
COPY entrypoint.sh /
RUN chmod 755 /usr/bin/aws-lambda-rie /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["app.lambda_handler"]