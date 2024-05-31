AC_DEFUN([PDNS_CHECK_LIBCRYPTO_PQC], [
  AC_REQUIRE([PDNS_CHECK_LIBCRYPTO])

  # Set the environment correctly for a possibly non-default OpenSSL path that was found by/supplied to PDNS_CHECK_LIBCRYPTO
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"
  save_LIBS="$LIBS"

  CPPFLAGS="$LIBCRYPTO_INCLUDES $CPPFLAGS"
  LDFLAGS="$LIBCRYPTO_LDFLAGS $LDFLAGS"
  LIBS="$LIBCRYPTO_LIBS $LIBS"

  # Compile a program that checks if oqs-provider is available.
  libcrypto_pqc=yes
  AC_RUN_IFELSE([
    AC_LANG_PROGRAM([
      #include <openssl/provider.h>
    ], [
      OSSL_PROVIDER *provider = OSSL_PROVIDER_load(0, "oqsprovider");
      if (provider) {
	if (OSSL_PROVIDER_unload(provider) == 1) {
	  return 0;
	}
      } else {
	return 1;
      }
    ])
  ], [
    libcrypto_pqc=yes
  ], [
    libcrypto_pqc=no
  ])

  AS_IF([test "x$libcrypto_pqc" = "xyes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_PQC], [1], [define to 1 if oqs-provider for openssl is available.])
  ])

  # Restore variables
  CPPFLAGS="$save_CPPFLAGS"
  LDFLAGS="$save_LDFLAGS"
  LIBS="$save_LIBS -loqs"
])
