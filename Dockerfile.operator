FROM alpine:3

RUN adduser -u 10000 -D -g '' starboard starboard

COPY operator /usr/local/bin/operator

USER starboard

ENTRYPOINT ["operator"]
