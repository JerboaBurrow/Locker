# Locker

Lightweight encrypted data store in Rust

- Quickly store and retrieve key-value pairs encrypted with ```RSA```

[![Cross platform](https://github.com/JerboaBurrow/Locker/actions/workflows/tests.yml/badge.svg)](https://github.com/JerboaBurrow/Locker/actions/workflows/tests.yml)

#### Caution this software has no independent security audit. However, cryptography is supplied by [OpenSSL](https://github.com/openssl/openssl) via [rust-openssl](https://github.com/sfackler/rust-openssl), use at your own risk.

```
Locker general usage (see also commands):

    locker entry {data}

    Specifying {data} will run locker in store mode, omitting
      it will run locker in retrieve mode.

    Locker will automatically find a private key (RSA) as 
      a .pem file, and a lkr file as a .lkr in the current
      directory (see options to specify paths)

    Options (see below) can be specified with - for options 
      without arguments, and -- for options with arguments

Locker commands:

    (print keys in a .lkr) locker show_keys

  Positional arguments:
  
    entry    must be specified, the entry to store or retrieve
    data     optional, if specified locker will attempt to 
               store data with the key given by entry
  
  Options:
  
    --k pem   path to (encrypted) RSA private key in pem 
               format

    --p pass  password for the pem file

    -o        overwrite a key

    --f lkr   path to .lkr file

Notes:

  In storage mode locker will backup the locker file's prior
    state. E.g. file.lkr will be backed-up as file.lkr.bk.

  When in storage mode a key collision will quit, -o '
    must be specified to overwrite data
```
