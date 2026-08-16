# phpredis — the fifth client of recon item 2, and the one that still speaks
# RESP2 unless told otherwise.
FROM php:8.3-cli
RUN yes '' | pecl install redis && docker-php-ext-enable redis
COPY app.php /app/app.php
ENTRYPOINT ["php", "/app/app.php"]
