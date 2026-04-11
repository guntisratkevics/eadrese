FROM php:8.2-cli

RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxslt1-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    && docker-php-ext-install soap xsl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

CMD ["php", "-a"]
