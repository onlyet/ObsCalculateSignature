#define _CRT_NONSTDC_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obs_sign.h"
#include "obs_util.h"
#include "obs_sha.h"

char const *sep = "\n";

static int compare(void const *kv1, void const *kv2) {
	KV *k1 = (KV*) kv1;
	KV *k2 = (KV*) kv2;
	return strcmp(k1->k, k2->k);
}

int const key_list_size = 52;

char const *key_list[] = {
		"CDNNotifyConfiguration", "acl", "append", "attname", "backtosource", "cors", "customdomain", "delete", "deletebucket", "directcoldaccess",
		"encryption", "inventory", "length", "lifecycle", "location", "logging", "metadata", "modify", "name", "notification", "orchestration", "partNumber", "policy",
		"position", "quota", "rename", "replication", "requestPayment", "response-cache-control", "response-content-disposition", "response-content-encoding",
		"response-content-language", "response-content-type", "response-expires", "restore", "select", "storageClass", "storagePolicy", "storageinfo", "tagging",
		"torrent", "truncate", "uploadId", "uploads", "versionId", "versioning", "versions", "website", "x-image-process", "x-image-save-bucket", "x-image-save-object",
		"x-obs-security-token"};

static int in_param_key_list(char const *key){
	for(int i=0;i<key_list_size;i++){
		if(strcmp(key, key_list[i])){
			return 1;
		}
	}
	return 0;
}

int get_string_to_sign(char const *method,
		KeyValueList const *headers, KeyValueList const *params,
		char const *bucket, char const *object, long expires, char **output) {
	int size = strlen(method) + strlen(sep);

	//deal with headers
	char *contentMd5 = NULL;
	char *contentType = NULL;
	char *dateOrExpire = NULL;

	if(expires > 0){
		dateOrExpire = (char*) malloc(32);
		ltoa(expires, dateOrExpire, 10);
		size += strlen(dateOrExpire) + strlen(sep);
	}

	KV *kvs = NULL;
	int count = 0;
	if (headers != NULL && headers->size > 0) {
		kvs = (KV*) malloc(sizeof(KV) * headers->size);
		for (int i = 0; i < headers->size; i++) {
			KV kv = headers->kvs[i];
			string_to_lower(kv.k);
			trim_string(kv.k);
			trim_string(kv.v);
			if (strcmp(kv.k, "content-md5") == 0) {
				contentMd5 = kv.v;
				size += strlen(contentMd5) + strlen(sep);
			} else if (strcmp(kv.k, "content-type") == 0) {
				contentType = kv.v;
				size += strlen(contentType) + strlen(sep);
			} else if ((strcmp(kv.k, "date") == 0) && dateOrExpire == NULL) {
				dateOrExpire = kv.v;
				size += strlen(dateOrExpire) + strlen(sep);
			} else if (strstr(kv.k, "x-obs-") == kv.k) {
				kvs[count++] = kv;
			}
		}

		if(count > 0){
			//do sort headers by key
			qsort(kvs, count, sizeof(KV), compare);
		}

		for (int i = 0; i < count; i++) {
			size += strlen(kvs[i].k) + 1 + strlen(kvs[i].v) + strlen(sep);
		}
	}


	//deal with params;
	KV *paramsKvs = NULL;
	int paramsCount = 0;
	if(params != NULL && params->size > 0){
		paramsKvs = (KV*) malloc(sizeof(KV) * params->size);
		for (int i = 0; i < params->size; i++) {
			KV kv = params->kvs[i];
			if(in_param_key_list(kv.k)){
				paramsKvs[paramsCount++] = kv;
			}
		}

		if(paramsCount > 0){
			qsort(paramsKvs, paramsCount, sizeof(KV), compare);
			// made this for '?'
			size += 1;
		}

		for (int i = 0; i < paramsCount; i++) {
			size += strlen(paramsKvs[i].k);
			if(strlen(paramsKvs[i].v) > 0){
				size += 1 + strlen(paramsKvs[i].v);
			}

			if(i != paramsCount - 1){
				// made this for '&'
				size += 1;
			}
		}
	}

	size += 1;
	if(bucket != NULL){
		size += strlen(bucket) + 1;
		if(object != NULL){
			size += strlen(object);
		}
	}

	char *head = (char*) malloc(size + 1);

	char *temp = head;
	*temp = '\0';

	temp = strcat(temp, method);
	temp = strcat(temp, sep);

	if (contentMd5 != NULL) {
		temp = strcat(temp, contentMd5);
	}
	temp = strcat(temp, sep);

	if (contentType != NULL) {
		temp = strcat(temp, contentType);
	}
	temp = strcat(temp, sep);

	if (dateOrExpire != NULL) {
		temp = strcat(temp, dateOrExpire);
		if(expires > 0){
			free(dateOrExpire);
		}
	}
	temp = strcat(temp, sep);

	//add CanonicalizedHeaders
	if (kvs != NULL) {
		for (int i = 0; i < count; i++) {
			temp = strcat(temp, kvs[i].k);
			temp = strcat(temp, ":");
			temp = strcat(temp, kvs[i].v);
			temp = strcat(temp, sep);
		}
		free(kvs);
	}

	//add CanonicalizedResource
	temp = strcat(temp, "/");
	if(bucket != NULL && strlen(bucket) > 0){
		temp = strcat(temp, bucket);
		temp = strcat(temp, "/");
		if(object != NULL && strlen(object) > 0){
			temp = strcat(temp, object);
		}
	}

	//add params
	if(paramsKvs != NULL){
		for (int i = 0; i < paramsCount; i++) {
			if(i == 0){
				temp = strcat(temp, "?");
			}
			temp = strcat(temp, paramsKvs[i].k);
			if(strlen(paramsKvs[i].v) > 0){
				temp = strcat(temp, "=");
				temp = strcat(temp, paramsKvs[i].v);
			}

			if(i != paramsCount - 1){
				temp = strcat(temp, "&");
			}
		}
		free(paramsKvs);
	}


	*output = head;
	return 0;
}

int get_signature_for_header_auth(char const *sk, char const *string_to_sign, char **output) {

	unsigned char hmac[20] = {0};
	hmac_sha1(hmac, (unsigned char*)sk, strlen(sk), (unsigned char*)string_to_sign, strlen(string_to_sign));

	*output = (char*) malloc(1024);
	memset(*output, 0, 1024);
	base64_encode(hmac, 20, *output);
	trim_string(*output);

	return 0;
}

int get_signature_for_url_auth(char const *sk, char const *string_to_sign, char **output) {
	unsigned char hmac[20] = {0};
	hmac_sha1(hmac, (unsigned char*)sk, strlen(sk), (unsigned char*)string_to_sign, strlen(string_to_sign));

	char *temp = (char*) malloc(1024);
	base64_encode(hmac, 20, temp);
	trim_string(temp);

	*output = (char*) malloc(1024);

	url_encode(*output, temp, strlen(temp));

	free(temp);
	return 0;
}
