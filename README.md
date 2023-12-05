# Locker

Lightweight encrypted data store in Rust

- Quickly store and retrieve key-value pairs encrypted with ```RSA```

[![Cross platform](https://github.com/JerboaBurrow/Locker/actions/workflows/tests.yml/badge.svg)](https://github.com/JerboaBurrow/Locker/actions/workflows/tests.yml)

#### Caution this software has no independent security audit. However, cryptography is supplied by [OpenSSL](https://github.com/openssl/openssl) via [rust-openssl](https://github.com/sfackler/rust-openssl), use at your own risk.

```
Locker is a lightweight encrypted key-value data store 
  written in Rust, using OpenSSL (via rust-openssl) 
  for cryptography.

The source code is licensed under the GPL V3 
  https://github.com/JerboaBurrow/Locker

Caution this software has no independent security audit. 
 However, cryptography is supplied by OpenSSL via rust-openssl, 
 use at your own risk.

Locker general usage:

    locker entry [data]

    []'d values are optional

    Specifying [data] will run locker in store mode, omitting
      it will run locker in retrieve mode.

    Locker will automatically find a private key (RSA) as 
      a .pem file, and a lkr file as a .lkr in the current
      directory (see options to specify paths)

    Options (see below) can be specified with - for options 
      without arguments, and -- for options with arguments

  Positional arguments:
  
    entry    can be specified, the entry to store or retrieve
    data     optional, if specified locker will attempt to 
               store data with the key given by entry
  
  Options:
  
    --k pem          path to (encrypted) RSA private key in pem 
                       format

    --p pass         password for the pem file

    -o               overwrite a key

    -d               delete a key

    --f lkr          path to .lkr file

    -show_keys       print all keys in .lkr file

    --gen_key [pem]  generates an AES256 encrypted RSA
                       private key (with passphrase).
                       Writes to [pem] if specified or
                       'locker.pem' if not

    --re_key [pem]   generates a new AES256 encrypted RSA
                       private key, and transfers data from 
                       locker file to a new locker file 
                       encrypted with the new key.
                       Writes the key to [pem] if specified 
                       or 'locker.pem' if not
    
    --import file    import data in JSON format
                       from file

    --export [file]  export data in JSON format.
                       if [file] is specified Locker
                       will output for [file], otherwise
                       data will be export to 'exported'
                       in the current directory


Notes:

  Locker will always create a backup copy of the given .lkr file
    as a .lkr.bk, when data is written in any context.

  By default if a key already exists Locker will not overwrite 
    its value. If you wish to re-write a key's value specify -o to 
    overwrite
```
