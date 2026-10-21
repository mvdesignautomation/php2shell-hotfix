# php2shell-hotfix

Temporary mitigation and upgrade helper for **PHP2Shell**:

| CVE | Advisory | What it is |
| --- | --- | --- |
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via out-of-memory corruption |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state |

Both are CVSS 4.0 **9.2**. They are in the PHP engine, so application code, framework middleware, and WAF rules inside PHP do not close them. mod_php, PHP-FPM, php-cgi, FrankenPHP, and LiteSpeed are in scope. Risk is highest on Apache mod_php.

**This repository is not the security patch.** The patch is the upstream PHP release. Cloning this repo does not replace the binary. It does three things only:

1. Tell you if the installed binary is older than the patched release.
2. Write the temporary settings the PHP project published, into every SAPI `conf.d` it can find.
3. Upgrade PHP packages that your OS already installed. It does not add third-party repositories and it does not compile PHP.

There is no exploit code in this repo.

## Patched releases (21 October 2026)

| Branch | Minimum fixed version |
| --- | --- |
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |

PHP 8.1 and older are end of life. Official source backports, not point releases:

- [PHP 7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619)
- [PHP 8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619)
- [PHP 8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)

Windows builds and source tarballs: [php.net/downloads](https://www.php.net/downloads.php).

Announcement: [php.net/archive/2026.php#2026-10-21-5](https://www.php.net/archive/2026.php#2026-10-21-5).

## Use

```bash
git clone https://github.com/mvdesignautomation/php2shell-hotfix.git
cd php2shell-hotfix
chmod +x bin/php2shell-hotfix.sh

# Read-only report
./bin/php2shell-hotfix.sh status

# Write the temporary ini drop-in. Needs root if conf.d is not writable.
sudo ./bin/php2shell-hotfix.sh mitigate --apply --restart

# Upgrade distro packages already installed, then look again
sudo ./bin/php2shell-hotfix.sh upgrade --apply
./bin/php2shell-hotfix.sh status

# After the new binary is actually running, remove the temporary drop-in
sudo ./bin/php2shell-hotfix.sh revert --apply --restart
```

`status`, `mitigate`, and `upgrade` are dry runs until you pass `--apply`.

Inspect another build:

```bash
./bin/php2shell-hotfix.sh status --php /usr/local/bin/php
```

## What `mitigate` writes

`99-php2shell-mitigation.ini` in each scan directory (`php --ini`, plus common Debian, RHEL, Alpine, official Docker, and Homebrew paths):

```ini
session.upload_progress.enabled = 0
memory_limit = -1
fatal_error_backtraces = 0
```

`fatal_error_backtraces` is written only for PHP 8.5. The other two are the administrative settings from the advisories. They must be set before request startup, so `ini_set()` and `.user.ini` do not count. Restart every worker after the file is in place.

`memory_limit=-1` turns off PHP's per-request memory limit. That is the published stopgap, and it is incomplete: a failed allocation can still hit the vulnerable path. Put a **cgroup or container** memory limit around the worker. **Do not use `RLIMIT_AS` or `RLIMIT_DATA`.** Those limits take the vulnerable `longjmp()` path.

Changing `error_reporting`, `display_errors`, or `log_errors` does nothing for CVE-2026-109619.

Pool and mod_php snippets, if you would rather set `php_admin_value` yourself:

- [share/fpm-pool.snippet.conf](share/fpm-pool.snippet.conf)
- [share/apache-modphp.snippet.conf](share/apache-modphp.snippet.conf)
- [share/99-php2shell-mitigation.ini](share/99-php2shell-mitigation.ini)

## What `upgrade` will and will not do

It runs the distro package manager against **already installed** `php*` packages:

- Debian/Ubuntu: `apt-get install --only-upgrade` on packages from `dpkg`
- RHEL, Fedora, Alma, Rocky, Amazon Linux: `dnf upgrade 'php*'` (or `yum`)
- Alpine: `apk upgrade php php-fpm php-cli`

It will not enable a PPA, write a repo file, or `curl | bash` a binary. If your vendor has not published the patched build yet, `status` stays `vulnerable` and you keep the drop-in until it does.

Docker images do not pick up a host package upgrade. Rebuild `FROM php:8.3.36` (or 8.2.35 / 8.4.27 / 8.5.12, once that tag exists) and redeploy.

## Verify

```bash
php -v
php --ri session | sed -n '1,40p'
php -i | grep -E 'memory_limit|upload_progress|fatal_error_backtraces'
bash tests/classify_test.sh
```

You want `PHP 8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`, or a later patch on that branch, and a worker restart after the package install. A host that still has the old binary loaded is still exposed.

## License

MIT. Not affiliated with the PHP Group. The vulnerabilities and the recommended settings are theirs; this script only applies them.
