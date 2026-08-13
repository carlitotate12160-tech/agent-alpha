# Laravel Real-World Lab — Dockerfile
# PHP 8.2 + Apache + Composer + Laravel 10.
# ARM64-compatible (php:8.2-apache has ARM64 variant).

FROM php:8.2-apache

# PHP extensions required by Laravel
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libzip-dev \
    libcurl4-openssl-dev \
    libonig-dev \
    && docker-php-ext-install \
    xml \
    zip \
    curl \
    pdo \
    pdo_mysql \
    mbstring \
    bcmath \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html

# Apache DocumentRoot → Laravel's public/
RUN sed -i 's!/var/www/html!/var/www/html/public!g' \
    /etc/apache2/sites-available/000-default.conf

# Laravel installed via seed.sh (composer create-project in the container).
# The app volume is mounted at /var/www/html — seed.sh runs composer there.
