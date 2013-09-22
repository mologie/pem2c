pem2c
=====

Command line tool for embedding PEM-encoded X509 certificates and public keys into C programs


### Compilation

Compile using `gcc pem2c.c -o pem2c -O2 -lcrypto` or download a precompiled binary for Windows from the [releases](https://github.com/mologie/pem2c/releases) section.

### Command-line

This utility reads the PEM-encoded file from stdin, and writes a header file to stdout. The first argument describes the file type, the second argument the macro name used in the header file:

`pem2c x509 MY_MACRO_NAME <my-certificate.pem >my-header.h`

Note that pem2c can process multiple certificate files for building certificate chains:

`cat my-root-ca.pem my-intermediate-ca.pem | pem2c x509 MY_CERT_CHAIN >my-ca-header.h`

### Loading certificates

The following function imports a certificate chain back into a X509_STORE object:
```c++
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
```c++
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
```c++
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
