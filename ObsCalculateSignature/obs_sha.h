
#define EOK (0)

#ifndef errno_t
typedef int errno_t;
#endif

void hmac_sha1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len);
