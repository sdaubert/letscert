[![Gem Version](https://badge.fury.io/rb/letscert.svg)](https://badge.fury.io/rb/letscert)

# letscert
A simple `Let's Encrypt` client in ruby.

I think `simp_le` do it the right way: it is simple, it is safe as it does not need to be
run as root, but it is Python (no one is perfect :-)) So I started to create a clone, but
in Ruby.

# Usage

## Generate a key pair and get signed certificate:
With full chain support (`fullchain.pem` file will contain all certificates):

```bash
letscert -d example.com:/var/www/example.com/html --email my.name@domain.tld \
  -f account_key.json -f key.pem -f fullchain.pem
```

else (certificate for example.com is in `cert.pem` file, rest of certification chain
is in `chain.pem`):

```bash
letscert -d example.com:/var/www/example.com/html --email my.name@domain.tld \
  -f account_key.json -f key.pem -f cert.pem -f chain.pem
```

Commands are the sames for certificate renewal.


## Generate a key pair and get a signed certificate for multi-domains:
Generate a single certificate for `example.com` and `www.example.com`:

```bash
letscert -d example.com -d www.example.com --default-root /var/www/html \
  --email my.name@domain.tld -f account_key.json -f key.pem -f fullchain.pem
```

Command is the same for certificate renewal.

## Generate a key pair and get a signed certificate if existing one is valid for less than xx days

In this example, `xx` is 10:

```bash
letscert -d example.com:/var/www/example.com/html --email my.name@domain.tld \
  -f account_key.json -f key.pem -f cert.pem -f chain.pem --valid-min 10d
```

Valid time may also be set as number of hours (`h` suffix), minutes (`m` suffix) or
seconds (no suffix).

## Revoke a key pair:
From directory where are stored `account_key.json` and `cert.pem` or `fullchain.pem`:

```bash
letscert -d example.com:/var/www/example.com/html --email my.name@domain.tld --revoke
```


# What `letscert` do

* Automagically create a new ACME account if needed.
* Issue new certificate if no previous one found.
* Renew certificate only if needed.
* Only `http-01` challenge supported. An existing web server must be alreay running.
  `letscert` should have write access to `${webroot}/.well-known/acme-challenge`.
* Crontab friendly: no prompts.
* No configuration file.
* Support multiple domains with multiple roots. Always create a single certificate per
  run (ie a certificate may have multiple SANs).
* As `simp_le`, check the exit code to known if a renewal has happened:
  * 0 if certificate data was created or updated;
  * 1 if renewal not necessary;
  * 2 in case of errors.

# Installation
`letscert` is cryptographically signed. To be sure the gem you install hasn’t been tampered:
* add my public key as a trusted certificate:
```
gem cert --add <(curl -Ls https://raw.github.com/metricfu/metric_fu/master/certs/gem-public_cert.pem)
```
* install letscert gem with a policy:
```
gem install letscert -P MediumSecurity
```

The MediumSecurity trust profile will verify signed gems, but allow the installation of unsigned dependencies. This is necessary because not all of letcert’s dependencies are signed, so we cannot use HighSecurity.