#!/bin/bash
# Setup Laravel lab target with debug mode enabled for C6 testing
# Run this on Oracle ARM64 box

set -e

echo "=== Setting up Laravel lab target ==="

# Install dependencies
echo "Installing PHP and Composer..."
sudo apt update
sudo apt install -y php php-xml php-mbstring php-curl php-zip php-bcmath php-sqlite3 php-mysql unzip

# Install Composer if not exists
if ! command -v composer &> /dev/null; then
    echo "Installing Composer..."
    cd /tmp
    curl -sS https://getcomposer.org/installer | php
    sudo mv composer.phar /usr/local/bin/composer
    sudo chmod +x /usr/local/bin/composer
    export PATH="/usr/local/bin:$PATH"
fi

# Create Laravel project
echo "Creating Laravel project..."
cd /home/ubuntu
if [ -d "lab-target" ]; then
    echo "lab-target directory already exists, removing..."
    rm -rf lab-target
fi

/usr/local/bin/composer create-project laravel/laravel lab-target
cd lab-target

# Enable debug mode
echo "Enabling debug mode..."
sed -i 's/APP_DEBUG=false/APP_DEBUG=true/' .env

# Generate app key
echo "Generating app key..."
php artisan key:generate

# Create trigger-error route for testing
echo "Creating trigger-error route..."
cat > routes/web.php << 'EOF'
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/trigger-error', function () {
    // Trigger database error for debug page
    try {
        DB::connection()->getPdo();
        throw new \Exception('Test error for Laravel debug page');
    } catch (\Exception $e) {
        // This will trigger Laravel debug page if APP_DEBUG=true
        throw $e;
    }
});
EOF

echo "=== Laravel lab target setup complete ==="
echo "To start the server, run:"
echo "  cd /home/ubuntu/lab-target"
echo "  php artisan serve --host=0.0.0.0 --port=8080"
echo ""
echo "To test, run:"
echo "  curl http://localhost:8080/trigger-error"
