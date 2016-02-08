# letscert
A simple `Let's Encrypt` client in ruby.

I think `simp_le` do it the right way: it is simple, it is safe as it does not need to be
run as root, but it is Python (no one is perfect :-)) So I started to create a clone, but
in Ruby.

# Usage

Generate a key pair and get signed certificate:
```bash
letscert -d example.com:/var/www/example.com/html -f account_key.json -f key.pem -f cert.pem -f fullchain.pem
```

Generate a key pair and get a signed certificate for multi-domains:
```bash
letscert -d example.com -d www.example.com --default_root /var/www/html -f account_key.json -f key.pem -f cert.pem -f fullchain.pem
```

Commands are the sames for certificate renewal.

# What `letscert` do

* Automagically a new ACME account if needed.
* Issue new certificate if no previous one found.
* Renew certificate only if needed.
* Only `http-01` challenge supported. An existing web server must be alreay running. `letscert` should have write access to `${webroot}/.well-known/acme-challenge`.
* Crontab friendly: no promts.
* No configuration file.
* Support multiple domains with multiple roots. Always create a single certificate per un
  (ie a certificate may have multiple SANs).
* As `simp_le`, check the exit code to known if a renewal has happened:
  * 0 if certificate data was created or updated;
  * 1 if renewal not necessary;
  * 2 in case of errors.

# Todo
Add support to revocation.