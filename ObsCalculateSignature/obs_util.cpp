

#include <stdlib.h>
#include <string.h>
#include "obs_util.h"
#include <ctype.h>

char* new_string(char const *org) {
	char *ret = (char*) malloc(strlen(org) + 1);
	strcpy(ret, org);
	return ret;
}

static char to_lower(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	}

	return c;
}

void string_to_lower(char *str) {
	for (; *str != '\0'; str++) {
		*str = to_lower(*str);
	}
}

static int is_space(char c) {
	return (c == ' ') || (c == '\t') || (c == '\n');
}

char *trim_string(char *str) {
	int len = strlen(str);
	int start = 0;

	if (len == 0){
		return str;
	}

	for (; len > 0 && is_space(str[len - 1]); len--);


	for (; start < len && is_space(str[start]); start++);

	if(len - start > 0){
		memcpy(str, str + start, len - start);
	}

	str[len-start] = '\0';
	return str;
}


int base64_encode(const unsigned char *in, int inLen, char *out)
{
    static const char *ENC =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char *original_out = out;

    while (inLen) {
        // first 6 bits of char 1
        *out++ = ENC[*in >> 2];
        if (!--inLen) {
            // last 2 bits of char 1, 4 bits of 0
            *out++ = ENC[(*in & 0x3) << 4];
            *out++ = '=';
            *out++ = '=';
            break;
        }
        // last 2 bits of char 1, first 4 bits of char 2
        *out++ = ENC[((*in & 0x3) << 4) | (*(in + 1) >> 4)];
        in++;
        if (!--inLen) {
            // last 4 bits of char 2, 2 bits of 0
            *out++ = ENC[(*in & 0xF) << 2];
            *out++ = '=';
            break;
        }
        // last 4 bits of char 2, first 2 bits of char 3
        *out++ = ENC[((*in & 0xF) << 2) | (*(in + 1) >> 6)];
        in++;
        // last 6 bits of char 3
        *out++ = ENC[*in & 0x3F];
        in++, inLen--;
    }

    return (out - original_out);
}

int url_encode(char *dest, const char *src, int maxSrcSize)
{
    static const char *hex = "0123456789ABCDEF";

    int len = 0;
    unsigned char c;

    while (*src) {
        if (++len > maxSrcSize) {
            *dest = 0;
            return -1;
        }
        c = *src;
        if (isalnum(c) || (c == '-') || (c == '_') || (c == '.') || (c == '~')) {
            *dest++ = c;
        } else if (*src == ' ') {
            *dest++ = '%';
            *dest++ = '2';
            *dest++ = '0';
        } else {
            *dest++ = '%';
            *dest++ = hex[c >> 4];
            *dest++ = hex[c & 15];
        }
        src++;
    }

    *dest = 0;

    return 0;
}

