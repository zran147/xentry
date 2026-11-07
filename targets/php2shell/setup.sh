#!/usr/bin/env bash
# PHP 8.4.26 + Apache mod_php target setup. Runs as root in the target VM.
# Args: mirror_url php_artifact_id php_sha256
set -euo pipefail

mirror_url="${1:?mirror_url}"
artifact_id="${2:?php_artifact_id}"
expected_sha="${3:?php_sha256}"
src_dir="/usr/local/src/php-8.4.26"
tarball="/tmp/php-8.4.26.tar.xz"

mkdir -p /usr/local/src /etc/php/conf.d /var/lib/php/sessions /var/lib/xentry /var/www/html
curl -fsS --retry 3 --connect-timeout 15 --max-time 300 \
  "$mirror_url/artifacts/$artifact_id" -o "$tarball"
echo "$expected_sha  $tarball" | sha256sum -c -

rm -rf "$src_dir"
tar -xJf "$tarball" -C /usr/local/src
cd "$src_dir"
./configure \
  --with-apxs2=/usr/bin/apxs \
  --with-config-file-path=/etc/php \
  --with-config-file-scan-dir=/etc/php/conf.d \
  --enable-mbstring \
  --enable-opcache \
  --enable-ftp \
  --with-curl \
  --with-openssl \
  --with-zlib \
  --with-libxml \
  --with-sqlite3 \
  --with-readline
make -j"$(nproc)"
make install

# Keep the built-in defaults; php.ini-production changes output buffering and
# assertion behavior, which the pinned PoC's infoleak depends on.
rm -f /etc/php/php.ini
cat > /etc/php/conf.d/zz-poc.ini <<'INI'
display_errors = On
display_startup_errors = On
memory_limit = 8M
max_input_vars = 1000
file_uploads = On
upload_max_filesize = 64M
post_max_size = 64M
session.save_path = "/var/lib/php/sessions"
session.use_cookies = 1
session.use_strict_mode = 0
session.serialize_handler = php
session.upload_progress.enabled = 1
session.upload_progress.cleanup = 1
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
max_multipart_body_parts = 5000
zend_extension=opcache
INI

a2dismod mpm_event >/dev/null 2>&1 || true
a2enmod mpm_prefork >/dev/null
cat > /etc/apache2/conf-enabled/zz-prefork.conf <<'CONF'
StartServers 1
MinSpareServers 1
MaxSpareServers 1
MaxRequestWorkers 1
MaxConnectionsPerChild 0
CONF
cat > /etc/apache2/conf-enabled/xentry-php.conf <<'CONF'
LoadModule php_module /usr/lib/apache2/modules/libphp.so
<FilesMatch \.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
DirectoryIndex index.php
CONF
printf 'Listen 8088\n' > /etc/apache2/ports.conf
cat > /etc/apache2/sites-available/xentry.conf <<'CONF'
<VirtualHost *:8088>
  DocumentRoot /var/www/html
  <Directory /var/www/html>
    AllowOverride None
    Require all granted
  </Directory>
  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
CONF
a2dissite 000-default >/dev/null 2>&1 || true
a2ensite xentry >/dev/null

printf '<?php echo "ok\\n";\n' > /var/www/html/index.php
rm -f /var/www/html/index.html
chown -R www-data:www-data /var/www/html /var/lib/php/sessions
chmod 755 /var/lib/xentry

apache2ctl configtest
systemctl restart apache2 2>/dev/null || apache2ctl restart
test "$(php -r 'echo PHP_VERSION;')" = "8.4.26"
printf '8.4.26\n' > /var/lib/xentry/setup-php.done
