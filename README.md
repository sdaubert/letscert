[![Gem Version](https://badge.fury.io/rb/letscert.svg)](https://badge.fury.io/rb/letscert)
[![Build Status](https://travis-ci.org/sdaubert/letscert.svg?branch=master)](https://travis-ci.org/sdaubert/letscert)

# letscert
A simple `Let's Encrypt` client in ruby.

I think [kuba/simp_le](https://github.com/kuba/simp_le) do it the right way: it is simple, it is safe as it does not need to be
run as root, but it is Python (no one is perfect :-)) So I started to create a clone, but
in Ruby.

# Usage

## Generate a key pair and get signed certificate:
With full chain support (`fullchain.pem` file will contain all certificates):

```bash
letscert -d example.org:/var/www/example.org/html --email my.name@example.org \
  -f account_key.json -f key.pem -f fullchain.pem
```

else (certificate for example.org is in `cert.pem` file, rest of certification chain
is in `chain.pem`):

```bash
letscert -d example.org:/var/www/example.org/html --email my.name@example.org \
  -f account_key.json -f key.pem -f cert.pem -f chain.pem
```

Commands are the sames for certificate renewal.


## Generate a key pair and get a signed certificate for multi-domains:
Generate a single certificate for `example.org` and `www.example.org`:

```bash
letscert -d example.org -d www.example.org --default-root /var/www/html \
  --email my.name@example.org -f account_key.json -f key.pem -f fullchain.pem
```

Command is the same for certificate renewal.

## Generate a key pair and get a signed certificate if existing one is valid for less than xx days

In this example, `xx` is 10:

```bash
letscert -d example.org:/var/www/example.org/html --email my.name@example.org \
  -f account_key.json -f key.pem -f cert.pem -f chain.pem --valid-min 10d
```

Valid time may also be set as number of hours (`h` suffix), minutes (`m` suffix) or
seconds (no suffix).

## Revoke a key pair:
From directory where are stored `account_key.json` and `cert.pem` or `fullchain.pem`:

```bash
letscert -d example.org:/var/www/example.org/html --email my.name@example.org --revoke
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
* Check the exit code to known if a renewal has happened:
  * 0 if certificate data was created or updated;
  * 1 if renewal not necessary;
  * 2 in case of errors.

# Installation
Since v0.4.1, `letscert` is cryptographically signed. To be sure the gem you install
hasn’t been tampered:
* add my public key as a trusted certificate:
```
gem cert --add <(curl -Ls https://raw.github.com/sdaubert/letscert/master/certs/gem-public_cert.pem)
```
* install letscert gem with a policy:
```
gem install letscert -P MediumSecurity
```

The MediumSecurity trust profile will verify signed gems, but allow the installation of
unsigned dependencies. This is necessary because not all of letcert’s dependencies are
signed, so we cannot use HighSecurity.
