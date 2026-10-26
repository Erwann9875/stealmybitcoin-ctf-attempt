FROM php:8.4.26-cli@sha256:e2432ac85c3454004d89e3d75615abd2d205b7ffb9590e586fad1a053f016bb3

WORKDIR /app
COPY lab/ /app/
COPY print-flag /usr/local/bin/print-flag
RUN chmod 0755 /usr/local/bin/print-flag

EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000"]
