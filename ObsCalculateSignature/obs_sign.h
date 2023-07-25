


typedef struct{
	char *k;
	char *v;
} KV;

typedef struct{
	KV *kvs;
	int size;
} KeyValueList;


int get_string_to_sign(char const *method,  KeyValueList const *headers, KeyValueList const *params, char const *bucket, char const *object,
		long expires, char **output);

int get_signature_for_header_auth(char const *sk, char const *string_to_sign, char **output);

int get_signature_for_url_auth(char const *sk, char const *string_to_sign, char **output);
