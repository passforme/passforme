# The passforme sync server as a container, for those who self-host with
# Docker. It packages the binary that release.yml has already built and
# tested on each architecture's own runner; it never compiles. The build
# context holds linux/amd64/passforme-server and linux/arm64/passforme-server.
#
# The server speaks plain HTTP and the client requires HTTPS: publish the
# port on 127.0.0.1 only and put HTTPS in front (docs/self-hosting.md).
FROM debian:trixie-slim

ARG TARGETPLATFORM

RUN useradd --system --uid 10001 --user-group --home-dir /data \
      --shell /usr/sbin/nologin passforme \
 && install -d -o passforme -g passforme -m 0700 /data

COPY --chmod=755 ${TARGETPLATFORM}/passforme-server /usr/local/bin/passforme-server

USER passforme
VOLUME /data
EXPOSE 8090

ENTRYPOINT ["passforme-server", "--data", "/data"]
CMD ["serve", "--listen", "0.0.0.0:8090"]
