
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obs_sign.h"
#include "obs_util.h"

const int size = 100;


void init_headers(KeyValueList **headers) {
	*headers = (KeyValueList*) malloc(sizeof(KeyValueList));
	(*headers)->size = 3;
	(*headers)->kvs = (KV*) malloc(3 * sizeof(KV));
	KV *kvs = (*headers)->kvs;

	kvs[0].k = new_string("Content-MD5");
	kvs[0].v = new_string(/*"vaBE3Ai+/iSRwsl3A=="*/"");

	kvs[1].k = new_string("Content-Type");
	kvs[1].v = new_string(/*"application/xml"*/"");

	kvs[2].k = new_string("Date");
	kvs[2].v = new_string("Mon, 17 Jul 2023 08:02:15 GMT");

	//kvs[3].k = new_string("Content-Length");
	//kvs[3].v = new_string("363");

	//kvs[4].k = new_string("x-obs-meta-key");
	//kvs[4].v = new_string("test");

	//kvs[5].k = new_string("x-obs-storage-class");
	//kvs[5].v = new_string("WARM");
}

void destory(KeyValueList *kvlist) {
	if (!kvlist) return;
	for (int i = 0; i < kvlist->size; i++) {
		free(kvlist->kvs[i].k);
		free(kvlist->kvs[i].v);
	}

	free(kvlist->kvs);
	free(kvlist);
}

void init_params(KeyValueList **params) {
	*params = (KeyValueList*) malloc(sizeof(KeyValueList));
	(*params)->size = 1;
	(*params)->kvs = (KV*) malloc(1 * sizeof(KV));
	KV *kvs = (*params)->kvs;

	kvs[0].k = new_string("acl");
	kvs[0].v = new_string("");
}

void test_header_auth(){
	char *string_to_sign;

	KeyValueList *headers;
	init_headers(&headers);

	KeyValueList *params = nullptr;
	//init_params(&params);

	get_string_to_sign("PUT", headers, params, "bucketname",
			/*"objectname"*/"qwer.png", -1, &string_to_sign);
	printf("%s\n", string_to_sign);


	const char *sk = /*"<your security key id>"*/"FADSJ0234HT2043TGFF134";
	char *signature;
	get_signature_for_header_auth(sk, string_to_sign, &signature);
	printf("\nsignature: %s\n", signature);

	const char* ak = "ASDFQWPEJFPQE";
	printf("Authorization: OBS %s:%s", ak, signature);

	free(signature);
	free(string_to_sign);
	destory(headers);
	destory(params);
}

//void test_url_auth(){
//	char *string_to_sign;
//
//	get_string_to_sign("GET", NULL, NULL, "bucketname",
//			"objectname", 1644485441, &string_to_sign);
//	printf("%s\n", string_to_sign);
//
//
//	char *sk = "<your security key id>";
//	char *signature;
//	get_signature_for_url_auth(sk, string_to_sign, &signature);
//	printf("%s\n", signature);
//
//	free(signature);
//	free(string_to_sign);
//}

int main(void) {
	test_header_auth();
//	test_url_auth();
	return 0;
}
