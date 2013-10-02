pem2c
=====

Command line tool for embedding PEM-encoded X509 certificates and public keys into C programs. It translates this:

```
-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
...
O3NJo2pXh5Tl1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6V
um0ABj6y6koQOdjQK/W/7HW/lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkySh
NOsF/5oirpt9P/FlUQqmMGqz9IgcgA38corog14=
-----END CERTIFICATE-----
```

... into this:

```c
// File generated by pem2c 1.0.1 - do not edit
#pragma once
#define STARTCOM_CA { \
    /* CN = 'StartCom Certification Authority', 1997 bytes */ \
    0x30, 0x82, 0x07, 0xC9, 0x30, 0x82, 0x05, 0xB1, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, \
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, \
    0x7D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x49, 0x4C, 0x31, 0x16, \
    ... \
    0x43, 0x62, 0x20, 0xCA, 0xE7, 0x56, 0x4B, 0x65, 0xEA, 0xFE, 0x6C, 0xC1, 0x24, 0x93, 0x24, 0xA1, \
    0x34, 0xEB, 0x05, 0xFF, 0x9A, 0x22, 0xAE, 0x9B, 0x7D, 0x3F, 0xF1, 0x65, 0x51, 0x0A, 0xA6, 0x30, \
    0x6A, 0xB3, 0xF4, 0x88, 0x1C, 0x80, 0x0D, 0xFC, 0x72, 0x8A, 0xE8, 0x83, 0x5E \
    }
```


### Compilation

Compile using `gcc pem2c.c -o pem2c -O2 -lcrypto`, use the CMake project, or download a precompiled binary for Windows from the [release](https://github.com/mologie/pem2c/releases) section. OpenSSL and its headers must are required.

### Command-line

This utility reads a PEM-encoded file from disk or stdin, and writes a header file to disk or stdout. The first unnamed argument describes the file type, which is either 'x509' or 'pubkey', and the second argument the macro name used in the header file:

`pem2c [-i in.pem] [-o out.h] <x509|pubkey> <macro>`

Note that pem2c can process multiple certificate files for building certificate chains:

`cat my-root-ca.pem my-intermediate-ca.pem | pem2c x509 MY_CERT_CHAIN >my-ca-header.h`

### Loading certificates

The following function imports a certificate chain back into a X509_STORE object:
```c
#include <my-ca-header.h>
#include <stddef.h>

void load_certificate_chain(X509_STORE* certificate_store)
{
    static const unsigned char cert_chain_der[] = MY_CERT_CHAIN;
    const unsigned char* cert_chain_der_ptr = cert_chain_der;
    const unsigned char* cert_chain_der_end = cert_chain_der_ptr + sizeof(cert_chain_der);

    ptrdiff_t length;

    while (length = (ptrdiff_t)cert_chain_der_end - (ptrdiff_t)cert_chain_der_ptr)
    {
        X509* x = d2i_X509(0, &cert_chain_der_ptr, (long)length);

        if (!x)
        {
            abort();
        }

        if (X509_STORE_add_cert(certificate_store, x) != 1)
        {
            abort();
        }

        X509_free(x);
    }
}
```

Here is the same for a single certificate:
```c
#include <my-ca-header.h>

void load_certificate(X509_STORE* certificate_store)
{
    static const unsigned char cert_chain_der[] = MY_CERT_CHAIN;
    const unsigned char* cert_chain_der_ptr = cert_chain_der;
    X509* x = d2i_X509(0, &cert_chain_der_ptr, sizeof(cert_chain_der));

    if (!x)
    {
        abort();
    }

    if (X509_STORE_add_cert(certificate_store, x) != 1)
    {
        abort();
    }

    X509_free(x);
}
```

Public keys can be loaded using a similar method:
```c
#include <my-public-key.h>

EVP_PKEY* load_pubkey()
{
    static const unsigned char my_pubkey_der[] = MY_PUBLIC_KEY;
    const unsigned char* my_pubkey_der_ptr = my_pubkey_der;

    EVP_PKEY* pubkey = d2i_PUBKEY(0, &my_pubkey_der_ptr, sizeof(my_pubkey_der));

    if (!pubkey)
    {
        abort();
    }

    return pubkey;
}
```
