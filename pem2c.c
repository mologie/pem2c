// pem2c - convert PEM-encoded X509 certificate and public key files to C header files
// Oliver Kuckertz, 2013-10-02, public domain

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

#define PEM2C_VERSION "1.0.1"

static
int process_x509_pem(BIO* in_bp, BIO* out_bp)
{
	X509* x;
	int   cert_count = 0;

	while (x = PEM_read_bio_X509(in_bp, NULL, NULL, NULL))
	{
		unsigned char* cert = NULL;
		int            cert_len;
		X509_NAME*     cert_subject_name;
		char           cert_cn[256];
		int            i;

		cert_len = i2d_X509(x, &cert);

		if (cert_len < 0)
		{
			fprintf(stderr, "i2d_X509 failed\n");
			return 1;
		}

		cert_subject_name = X509_get_subject_name(x);
		X509_NAME_get_text_by_NID(cert_subject_name, NID_commonName, cert_cn, sizeof(cert_cn));

		if (cert_count)
		{
			BIO_printf(out_bp, ",");
		}

		BIO_printf(out_bp, " \\\n    ");
		BIO_printf(out_bp, "/* CN = '%s', %d bytes */ \\\n    ", cert_cn, cert_len);

		for (i = 0; i < cert_len - 1; i++)
		{
			BIO_printf(out_bp, "0x%02X, ", cert[i]);

			if (i && (i + 1) % 16 == 0)
			{
				BIO_printf(out_bp, "\\\n    ");
			}
		}

		BIO_printf(out_bp, "0x%02X", cert[i]);

		cert_count++;

		OPENSSL_free(cert);
	}

	return (cert_count != 0) ? 0 : 1;
}

static
int process_pubkey_pem(BIO* in_bp, BIO* out_bp)
{
	EVP_PKEY* pkey;
	int       cert_count = 0;

	while (pkey = PEM_read_bio_PUBKEY(in_bp, NULL, NULL, NULL))
	{
		unsigned char* pkey_der = NULL;
		int            pkey_der_len;
		int            i;

		pkey_der_len = i2d_PUBKEY(pkey, &pkey_der);

		if (pkey_der_len < 0)
		{
			fprintf(stderr, "i2d_PUBKEY failed\n");
			return 1;
		}

		if (cert_count)
		{
			BIO_printf(out_bp, ",");
		}

		BIO_printf(out_bp, " \\\n    ");

		for (i = 0; i < pkey_der_len - 1; i++)
		{
			BIO_printf(out_bp, "0x%02X, ", pkey_der[i]);

			if (i && (i + 1) % 16 == 0)
			{
				BIO_printf(out_bp, "\\\n    ");
			}
		}

		BIO_printf(out_bp, "0x%02X", pkey_der[i]);

		cert_count++;

		OPENSSL_free(pkey_der);
	}

	return (cert_count != 0) ? 0 : 1;
}

static
void print_usage(const char* prog_name)
{
	fprintf(stderr, "pem2c " PEM2C_VERSION "\n");
	fprintf(stderr, "usage: %s [-i in.pem] [-o out.h] <x509|pubkey> <macro>\n", prog_name);
}

int main(int argc, char* argv[])
{
	typedef int (*process_func)(BIO* in_bp, BIO* out_bp);

	BIO*         in_bp = NULL;
	BIO*         out_bp = NULL;
	char*        macro_name;
	char*        pem_type;
	process_func process;
	int          result = 1;

	char** arg_ptr = argv + 1;
	char** arg_end_ptr = argv + argc;

	while (arg_ptr != arg_end_ptr)
	{
		char* arg = *arg_ptr;
		int args_remaining = arg_end_ptr - arg_ptr;
		int have_parameter = args_remaining > 1;

		if (arg[0] == '-')
		{
			if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0)
			{
				print_usage(argv[0]);
				result = 0;
				goto cleanup;
			}
			else if (strcmp(arg, "-i") == 0)
			{
				if (in_bp)
				{
					fprintf(stderr, "duplicated option: -i\n");
					goto cleanup;
				}

				if (!have_parameter)
				{
					fprintf(stderr, "option -i requires a parameter\n");
					goto cleanup;
				}
				else
				{
					char* filename = *(++arg_ptr);

					in_bp = BIO_new_file(filename, "r");

					if (!in_bp)
					{
						fprintf(stderr, "failed to open input file: %s\n", filename);
						goto cleanup;
					}
				}
			}
			else if (strcmp(arg, "-o") == 0)
			{
				if (out_bp)
				{
					fprintf(stderr, "duplicated option: -o\n");
					goto cleanup;
				}

				if (!have_parameter)
				{
					fprintf(stderr, "option -o requires a parameter\n");
					goto cleanup;
				}
				else
				{
					char* filename = *(++arg_ptr);

					out_bp = BIO_new_file(filename, "w");

					if (!out_bp)
					{
						fprintf(stderr, "failed to open output file: %s\n", filename);
						goto cleanup;
					}
				}
			}
			else
			{
				fprintf(stderr, "invalid argument: %s\n", arg);
				goto cleanup;
			}

			arg_ptr++;
		}
		else
		{
			if (args_remaining < 2)
			{
				print_usage(argv[0]);
				goto cleanup;
			}

			pem_type = *(arg_ptr++);
			macro_name = *(arg_ptr++);
		}
	}

	if (!in_bp)
	{
		in_bp = BIO_new_fp(stdin, BIO_NOCLOSE);

		if (!in_bp)
		{
			fprintf(stderr, "BIO_new_fp failed\n");
			goto cleanup;
		}
	}

	if (!out_bp)
	{
		out_bp = BIO_new_fp(stdout, BIO_NOCLOSE);

		if (!out_bp)
		{
			fprintf(stderr, "BIO_new_fp failed\n");
			goto cleanup;
		}
	}
	
	if (strcmp(pem_type, "x509") == 0)
	{
		process = process_x509_pem;
	}
	else if (strcmp(pem_type, "pubkey") == 0)
	{
		process = process_pubkey_pem;
	}
	else
	{
		print_usage(argv[0]);
		goto cleanup;
	}

	BIO_printf(out_bp, "// File generated by pem2c " PEM2C_VERSION " - do not edit\n\n");
	BIO_printf(out_bp, "#pragma once\n\n");
	BIO_printf(out_bp, "#define %s {", macro_name);
	
	result = process(in_bp, out_bp);

	BIO_printf(out_bp, " \\\n    }\n");

cleanup:
	if (in_bp) BIO_free(in_bp);
	if (out_bp) BIO_free(out_bp);

	return result;
}
