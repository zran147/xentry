#!/usr/bin/env bash
# GitLab CE 19.2.5 target setup. Runs as root in the target VM.
# Args: proxy_url artifact_id sha256
set -euo pipefail
proxy_url="${1:?proxy_url}"
artifact_id="${2:?artifact_id}"
expected_sha="${3:?sha256}"
deb="/tmp/gitlab-ce_19.2.5-ce.0_amd64.deb"

curl -fsS --retry 3 --connect-timeout 15 --max-time 900 \
  "$proxy_url/artifacts/$artifact_id" -o "$deb"
echo "$expected_sha  $deb" | sha256sum -c -
# The shared target image may have Apache enabled at boot; GitLab's bundled
# Nginx needs port 80.
systemctl stop apache2 >/dev/null 2>&1 || apache2ctl stop >/dev/null 2>&1 || true
systemctl disable apache2 >/dev/null 2>&1 || true
dpkg -i "$deb"
cat > /etc/gitlab/gitlab.rb <<'RUBY'
external_url 'http://10.42.0.10'
nginx['gzip'] = "off"
puma['worker_processes'] = 2
sidekiq['concurrency'] = 5
prometheus_monitoring['enable'] = false
alertmanager['enable'] = false
node_exporter['enable'] = false
redis_exporter['enable'] = false
postgres_exporter['enable'] = false
gitlab_exporter['enable'] = false
RUBY
gitlab-ctl reconfigure

for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://10.42.0.10/users/sign_in || true)"
  if [ "$code" = "200" ] || [ "$code" = "302" ]; then
    printf 'gitlab-ready http=%s\n' "$code" > /var/lib/xentry/setup-gitlab.done
    exit 0
  fi
  sleep 5
done
echo "gitlab did not become ready" >&2
exit 1
