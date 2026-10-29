/* Known-answer probe over libssh2's public, network-free API. Output is diffed by mayhem/test.sh. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libssh2.h>

static const char KEY[] = { 0, 0, 0 }; /* base64 "AAAA" */
#define TM (LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_BASE64 | \
            LIBSSH2_KNOWNHOST_KEY_SSHRSA)
#define TC (LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | \
            LIBSSH2_KNOWNHOST_KEY_SSHRSA)

int main(void)
{
    LIBSSH2_SESSION *s;
    LIBSSH2_KNOWNHOSTS *kh;
    struct libssh2_knownhost *k = NULL, *got = NULL;
    char buf[256], *dec = NULL;
    size_t n = 0, i;
    const char **algs = NULL;
    int rc, found = 0;

    if(libssh2_init(0))
        return 1;
    s = libssh2_session_init();
    if(!s)
        return 1;

    rc = libssh2_base64_decode(s, &dec, &n, "Zm5vcmQ=", 8);
    printf("base64 rc=%d len=%zu val=%.*s\n", rc, n, (int)n, dec ? dec : "");
    free(dec);

    kh = libssh2_knownhost_init(s);
    rc = libssh2_knownhost_addc(kh, "example.com", NULL, "AAAA", 4, "cmt", 3,
                                TM, &k);
    printf("add rc=%d\n", rc);
    rc = libssh2_knownhost_checkp(kh, "example.com", 22, KEY, 3, TC, &got);
    printf("check-match rc=%d\n", rc);
    rc = libssh2_knownhost_checkp(kh, "other.org", 22, KEY, 3, TC, &got);
    printf("check-unknown rc=%d\n", rc);
    {
        static const char k2[] = { 0, 0, 1 };
        rc = libssh2_knownhost_checkp(kh, "example.com", 22, k2, 3, TC, &got);
        printf("check-mismatch rc=%d\n", rc);
    }
    rc = libssh2_knownhost_writeline(kh, k, buf, sizeof(buf), &n,
                                     LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    printf("write rc=%d len=%zu line=%s", rc, n, buf);

    rc = libssh2_knownhost_readline(kh, "host2.org ssh-ed25519 AAAA note\n",
                                    32, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    printf("readline rc=%d\n", rc);
    rc = libssh2_knownhost_get(kh, &got, k);
    printf("get rc=%d name=%s key=%s\n", rc, got ? got->name : "-",
           got ? got->key : "-");
    libssh2_knownhost_free(kh);

    rc = libssh2_session_supported_algs(s, LIBSSH2_METHOD_KEX, &algs);
    for(i = 0; rc > 0 && i < (size_t)rc; i++)
        if(!strcmp(algs[i], "curve25519-sha256"))
            found = 1;
    printf("kex-has-curve25519=%d\n", found);
    if(algs)
        libssh2_free(s, (void *)algs);

    rc = libssh2_session_method_pref(s, LIBSSH2_METHOD_KEX, "curve25519-sha256");
    printf("pref-good rc=%d\n", rc);
    rc = libssh2_session_method_pref(s, LIBSSH2_METHOD_KEX, "no-such-kex");
    printf("pref-bad rc=%d\n", rc);

    libssh2_session_free(s);
    libssh2_exit();
    return 0;
}
