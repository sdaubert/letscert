# letscert
A simple `Let's Encrypt` client in ruby.

I think `simp_le` do it the right way: it is simple, it is safe as it does not needed to be run as root,
but it is Python (no one is perfect :-)) So I started to create a clone, but in Ruby.

Work in progress.

# Usage

Generate a key pair and get signed certificate
```bash
letscert -d example.com:/var/www/example.com/html -f key.pem -f cert.pem -f fullchain.pem
```

The command is the same for certificate renewal.
