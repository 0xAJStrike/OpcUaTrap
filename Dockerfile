# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage — restores and publishes OpcUaTrap together with its LibUA fork.
# OpcUaTrap.csproj references ../../../LibUA/NET-Core/LibUA/LibUA.csproj, so the
# fork is cloned as a sibling of the OpcUaTrap source inside /src.
# ---------------------------------------------------------------------------
# LibUA multi-targets net6.0..net9.0, so the build SDK must support net9.0 even
# though OpcUaTrap itself is net8.0 (restore evaluates all of LibUA's targets).
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build

# The LibUA fork to build against (override with --build-arg to pin a commit/tag).
ARG LIBUA_REPO=https://github.com/0xAJStrike/LibUA.git
ARG LIBUA_REF=main

WORKDIR /src
RUN git clone --depth 1 --branch ${LIBUA_REF} ${LIBUA_REPO} /src/LibUA

# Copy the honeypot source (see .dockerignore for what is excluded).
COPY . /src/OpcUaTrap

# Framework-dependent publish (no native apphost — we launch via `dotnet OpcUaTrap.dll`).
RUN dotnet publish /src/OpcUaTrap/src/OpcUaTrap/OpcUaTrap.csproj \
        -c Release -o /app/publish /p:UseAppHost=false

# ---------------------------------------------------------------------------
# Runtime stage — minimal ASP.NET runtime, non-root, state persisted under /data.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

# Non-root user; /data holds runtime state (ServerCert.pem/ServerKey.pem + logs).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin opcua \
    && mkdir -p /data /app \
    && chown -R opcua:opcua /data /app

COPY --from=build --chown=opcua:opcua /app/publish /app

USER opcua
WORKDIR /data

ENV OPCUATRAP_PROFILE=oil-gas \
    OPCUATRAP_LOG_DIR=/data/logs \
    DOTNET_EnableDiagnostics=0

EXPOSE 4840
VOLUME ["/data"]

# Liveness: is the OPC UA listener accepting TCP on 4840?
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/4840' || exit 1

ENTRYPOINT ["dotnet", "/app/OpcUaTrap.dll"]
