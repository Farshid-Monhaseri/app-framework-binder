/*
 Copyright (C) 2015-2020 "IoT.bzh"

 author: José Bollo <jose.bollo@iot.bzh>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include <string.h>
#include <limits.h>
#include <stdio.h>

#include "wrap-json.h"
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif


void tclone(struct json_object *object)
{
	struct json_object *o;

	o = wrap_json_clone(object);
	if (!wrap_json_equal(object, o))
		printf("ERROR in clone or equal: %s VERSUS %s\n", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), json_object_to_json_string_ext(o, JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);

	o = wrap_json_clone_deep(object);
	if (!wrap_json_equal(object, o))
		printf("ERROR in clone_deep or equal: %s VERSUS %s\n", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), json_object_to_json_string_ext(o, JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);
}


void objcb(void *closure, struct json_object *obj, const char *key)
{
	const char *prefix = closure;
	printf("  %s {%s} %s\n", prefix ?: "", key ?: "[]", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE));
}

void arrcb(void *closure, struct json_object *obj)
{
	objcb(closure, obj, NULL);
}

void tforall(struct json_object *object)
{
	wrap_json_for_all(object, objcb, "wrap_json_for_all");
	wrap_json_optobject_for_all(object, objcb, "wrap_json_optobject_for_all");
	wrap_json_object_for_all(object, objcb, "wrap_json_object_for_all");
	wrap_json_optarray_for_all(object, arrcb, "wrap_json_optarray_for_all");
	wrap_json_array_for_all(object, arrcb, "wrap_json_array_for_all");
}

struct mix
{
	int n;
	struct json_object *pair[2];
};

void mixcb(void *closure, struct json_object *obj, const char *key)
{
	struct mix *mix = closure;

	if (!mix->n) {
		mix->pair[0] = json_object_new_object();
		mix->pair[1] = json_object_new_object();
	}
	json_object_object_add(mix->pair[mix->n & 1], key, json_object_get(obj));
	mix->n++;
}

void tmix(struct json_object *object)
{
	struct json_object *z;
	struct mix mix = { .n = 0 };

	wrap_json_object_for_all(object, mixcb, &mix);
	if (mix.n) {
		z = wrap_json_object_add(wrap_json_clone(mix.pair[0]), mix.pair[1]);
		if (!wrap_json_contains(z, mix.pair[0]))
			printf("  ERROR mix/1\n");
		if (!wrap_json_contains(z, mix.pair[1]))
			printf("  ERROR mix/2\n");
		if (!wrap_json_contains(z, object))
			printf("  ERROR mix/3\n");
		if (!wrap_json_contains(object, z))
			printf("  ERROR mix/4\n");
		if (!wrap_json_equal(object, z))
			printf("  ERROR mix/5\n");
		json_object_put(z);
		json_object_put(mix.pair[0]);
		json_object_put(mix.pair[1]);
	}
}

void p(const char *desc, ...)
{
	int rc;
	va_list args;
	struct json_object *result;

	va_start(args, desc);
	rc = wrap_json_vpack(&result, desc, args);
	va_end(args);
	if (!rc)
		printf("  SUCCESS %s\n\n", json_object_to_json_string_ext(result, JSON_C_TO_STRING_NOSLASHESCAPE));
	else
		printf("  ERROR[char %d err %d] %s\n\n", wrap_json_get_error_position(rc), wrap_json_get_error_code(rc), wrap_json_get_error_string(rc));
	tclone(result);
	json_object_put(result);
}

const char *xs[10];
int *xi[10];
int64_t *xI[10];
double *xf[10];
struct json_object *xo[10];
size_t xz[10];
uint8_t *xy[10];

int extrchk(const char *desc, const char **array, int length, va_list args)
{
	unsigned m, k;
	int n;

	if (!desc)
		return 0;

	n = 0;
	k = m = 0;
	while(*desc) {
		switch(*desc) {
		case '{':
		case '[': k = !(*desc - '{'); m = (m << 1) | k; break;
		case '}':
		case ']': m = m >> 1; k = m&1; break;
		case 's':
			if (!k)
				(void)va_arg(args, char**);
			else {
				if (n > length)
					return -1;
				array[n++] = va_arg(args, const char*);
			}
			break;
		case '%': (void)va_arg(args, size_t*); k = m&1; break;
		case 'n': k = m&1; break;
		case 'b':
		case 'i': (void)va_arg(args, int*); k = m&1; break;
		case 'I': (void)va_arg(args, int64_t*); k = m&1; break;
		case 'f':
		case 'F': (void)va_arg(args, double*); k = m&1; break;
		case 'o': (void)va_arg(args, struct json_object**), k = m&1; break;
		case 'O': (void)va_arg(args, struct json_object**); k = m&1; break;
		case 'y':
		case 'Y':
			(void)va_arg(args, uint8_t**);
			(void)va_arg(args, size_t*);
			k = m&1;
			break;
		default:
			break;
		}
		desc++;
	}
	return n;
}

const char *mkeys[5];

void tchk(struct json_object *object, const char *desc, const char **keys, int length, int qrc)
{
	int rm, rc;

	rm = wrap_json_match(object, desc, keys[0], keys[1], keys[2], keys[3], keys[4]);
	rc = wrap_json_check(object, desc, keys[0], keys[1], keys[2], keys[3], keys[4]);
	if (rc != qrc)
		printf("  ERROR DIFFERS[char %d err %d] %s\n", wrap_json_get_error_position(rc), wrap_json_get_error_code(rc), wrap_json_get_error_string(rc));
	if (rm != !rc)
		printf("  ERROR OF MATCH\n");
}

void u(const char *value, const char *desc, ...)
{
	unsigned m, k;
	int rc, n;
	va_list args;
	const char *d;
	struct json_object *object, *o;

	memset(xs, 0, sizeof xs);
	memset(xi, 0, sizeof xi);
	memset(xI, 0, sizeof xI);
	memset(xf, 0, sizeof xf);
	memset(xo, 0, sizeof xo);
	memset(xy, 0, sizeof xy);
	memset(xz, 0, sizeof xz);
	object = json_tokener_parse(value);
	va_start(args, desc);
	rc = wrap_json_vunpack(object, desc, args);
	va_end(args);
	if (rc)
		printf("  ERROR[char %d err %d] %s", wrap_json_get_error_position(rc), wrap_json_get_error_code(rc), wrap_json_get_error_string(rc));
	else {
		value = NULL;
		printf("  SUCCESS");
		d = desc;
		va_start(args, desc);
		k = m = 0;
		while(*d) {
			switch(*d) {
			case '{': m = (m << 1) | 1; k = 1; break;
			case '}': m = m >> 1; k = m&1; break;
			case '[': m = m << 1; k = 0; break;
			case ']': m = m >> 1; k = m&1; break;
			case 's': printf(" s:%s", k ? va_arg(args, const char*) : *(va_arg(args, const char**)?:&value)); k ^= m&1; break;
			case '%': printf(" %%:%zu", *va_arg(args, size_t*)); k = m&1; break;
			case 'n': printf(" n"); k = m&1; break;
			case 'b': printf(" b:%d", *va_arg(args, int*)); k = m&1; break;
			case 'i': printf(" i:%d", *va_arg(args, int*)); k = m&1; break;
			case 'I': printf(" I:%lld", (long long int)*va_arg(args, int64_t*)); k = m&1; break;
			case 'f': printf(" f:%f", *va_arg(args, double*)); k = m&1; break;
			case 'F': printf(" F:%f", *va_arg(args, double*)); k = m&1; break;
			case 'o': printf(" o:%s", json_object_to_json_string_ext(*va_arg(args, struct json_object**), JSON_C_TO_STRING_NOSLASHESCAPE)); k = m&1; break;
			case 'O': o = *va_arg(args, struct json_object**); printf(" O:%s", json_object_to_json_string_ext(o, JSON_C_TO_STRING_NOSLASHESCAPE)); json_object_put(o); k = m&1; break;
			case 'y':
			case 'Y': {
				uint8_t *p = *va_arg(args, uint8_t**);
				size_t s = *va_arg(args, size_t*);
				printf(" y/%d:%.*s", (int)s, (int)s, (char*)p);
				k = m&1;
				break;
				}
			default: break;
			}
			d++;
		}
		va_end(args);
	}
	printf("\n");
	va_start(args, desc);
	n = extrchk(desc, mkeys, (int)(sizeof mkeys / sizeof *mkeys), args);
	va_end(args);
	if (n < 0)
		printf("  ERROR: too much keys in %s\n", desc);
	else
		tchk(object, desc, mkeys, n, rc);
	tclone(object);
	tforall(object);
	tmix(object);
	printf("\n");
	json_object_put(object);
}

void c(const char *sx, const char *sy, int e, int c)
{
	int re, rc;
	struct json_object *jx, *jy;

	jx = json_tokener_parse(sx);
	jy = json_tokener_parse(sy);

	re = wrap_json_cmp(jx, jy);
	rc = wrap_json_contains(jx, jy);

	printf("compare(%s)(%s)\n", sx, sy);
	printf("   -> %d / %d\n", re, rc);

	if (!re != !!e)
		printf("  ERROR should be %s\n", e ? "equal" : "different");
	if (!rc != !c)
		printf("  ERROR should %scontain\n", c ? "" : "not ");

	printf("\n");
}

#define P(...) do{ printf("pack(%s)\n",#__VA_ARGS__); p(__VA_ARGS__); } while(0)
#define U(...) do{ printf("unpack(%s)\n",#__VA_ARGS__); u(__VA_ARGS__); } while(0)

int main()
{
	char buffer[4] = {'t', 'e', 's', 't'};

	P("n");
	P("b", 1);
	P("b", 0);
	P("i", 1);
	P("I", (uint64_t)0x123456789abcdef);
	P("f", 3.14);
	P("s", "test");
	P("s?", "test");
	P("s?", NULL);
	P("s#", "test asdf", 4);
	P("s%", "test asdf", (size_t)4);
	P("s#", buffer, 4);
	P("s%", buffer, (size_t)4);
	P("s++", "te", "st", "ing");
	P("s#+#+", "test", 1, "test", 2, "test");
	P("s%+%+", "test", (size_t)1, "test", (size_t)2, "test");
	P("{}", 1.0);
	P("[]", 1.0);
	P("o", json_object_new_int(1));
	P("o?", json_object_new_int(1));
	P("o?", NULL);
	P("O", json_object_new_int(1));
	P("O?", json_object_new_int(1));
	P("O?", NULL);
	P("{s:[]}", "foo");
	P("{s+#+: []}", "foo", "barbar", 3, "baz");
	P("{s:s,s:o,s:O}", "a", NULL, "b", NULL, "c", NULL);
	P("{s:**}", "a", NULL);
	P("{s:s*,s:o*,s:O*}", "a", NULL, "b", NULL, "c", NULL);
	P("[i,i,i]", 0, 1, 2);
	P("[s,o,O]", NULL, NULL, NULL);
	P("[**]", NULL);
	P("[s*,o*,O*]", NULL, NULL, NULL);
	P(" s ", "test");
	P("[ ]");
	P("[ i , i,  i ] ", 1, 2, 3);
	P("{\n\n1");
	P("[}");
	P("{]");
	P("[");
	P("{");
	P("[i]a", 42);
	P("ia", 42);
	P("s", NULL);
	P("+", NULL);
	P(NULL);
	P("{s:i}", NULL, 1);
	P("{ {}: s }", "foo");
	P("{ s: {},  s:[ii{} }", "foo", "bar", 12, 13);
	P("[[[[[   [[[[[  [[[[ }]]]] ]]]] ]]]]]");
	P("y", "???????hello>>>>>>>", (size_t)19);
	P("Y", "???????hello>>>>>>>", (size_t)19);
	P("{sy?}", "foo", "hi", (size_t)2);
	P("{sy?}", "foo", NULL, 0);
	P("{sy*}", "foo", "hi", (size_t)2);
	P("{sy*}", "foo", NULL, 0);

	U("true", "b", &xi[0]);
	U("false", "b", &xi[0]);
	U("null", "n");
	U("42", "i", &xi[0]);
	U("123456789", "I", &xI[0]);
	U("3.14", "f", &xf[0]);
	U("12345", "F", &xf[0]);
	U("3.14", "F", &xf[0]);
	U("\"foo\"", "s", &xs[0]);
	U("\"foo\"", "s%", &xs[0], &xz[0]);
	U("{}", "{}");
	U("[]", "[]");
	U("{}", "o", &xo[0]);
	U("{}", "O", &xo[0]);
	U("{\"foo\":42}", "{si}", "foo", &xi[0]);
	U("[1,2,3]", "[i,i,i]", &xi[0], &xi[1], &xi[2]);
	U("{\"a\":1,\"b\":2,\"c\":3}", "{s:i, s:i, s:i}", "a", &xi[0], "b", &xi[1], "c", &xi[2]);
	U("42", "z");
	U("null", "[i]");
	U("[]", "[}");
	U("{}", "{]");
	U("[]", "[");
	U("{}", "{");
	U("[42]", "[i]a", &xi[0]);
	U("42", "ia", &xi[0]);
	U("[]", NULL);
	U("\"foo\"", "s", NULL);
	U("42", "s", NULL);
	U("42", "n");
	U("42", "b", NULL);
	U("42", "f", NULL);
	U("42", "[i]", NULL);
	U("42", "{si}", "foo", NULL);
	U("\"foo\"", "n");
	U("\"foo\"", "b", NULL);
	U("\"foo\"", "i", NULL);
	U("\"foo\"", "I", NULL);
	U("\"foo\"", "f", NULL);
	U("\"foo\"", "F", NULL);
	U("true", "s", NULL);
	U("true", "n");
	U("true", "i", NULL);
	U("true", "I", NULL);
	U("true", "f", NULL);
	U("true", "F", NULL);
	U("[42]", "[ii]", &xi[0], &xi[1]);
	U("{\"foo\":42}", "{si}", NULL, &xi[0]);
	U("{\"foo\":42}", "{si}", "baz", &xi[0]);
	U("[1,2,3]", "[iii!]", &xi[0], &xi[1], &xi[2]);
	U("[1,2,3]", "[ii!]", &xi[0], &xi[1]);
	U("[1,2,3]", "[ii]", &xi[0], &xi[1]);
	U("[1,2,3]", "[ii*]", &xi[0], &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{sisi}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{sisi*}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{sisi!}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{si}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{si*}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42,\"baz\":45}", "{si!}", "baz", &xi[0], "foo", &xi[1]);
	U("[1,{\"foo\":2,\"bar\":null},[3,4]]", "[i{sisn}[ii]]", &xi[0], "foo", &xi[1], "bar", &xi[2], &xi[3]);
	U("[1,2,3]", "[ii!i]", &xi[0], &xi[1], &xi[2]);
	U("[1,2,3]", "[ii*i]", &xi[0], &xi[1], &xi[2]);
	U("{\"foo\":1,\"bar\":2}", "{si!si}", "foo", &xi[1], "bar", &xi[2]);
	U("{\"foo\":1,\"bar\":2}", "{si*si}", "foo", &xi[1], "bar", &xi[2]);
	U("{\"foo\":{\"baz\":null,\"bar\":null}}", "{s{sn!}}", "foo", "bar");
	U("[[1,2,3]]", "[[ii!]]", &xi[0], &xi[1]);
	U("{}", "{s?i}", "foo", &xi[0]);
	U("{\"foo\":1}", "{s?i}", "foo", &xi[0]);
	U("{}", "{s?[ii]s?{s{si!}}}", "foo", &xi[0], &xi[1], "bar", "baz", "quux", &xi[2]);
	U("{\"foo\":[1,2]}", "{s?[ii]s?{s{si!}}}", "foo", &xi[0], &xi[1], "bar", "baz", "quux", &xi[2]);
	U("{\"bar\":{\"baz\":{\"quux\":15}}}", "{s?[ii]s?{s{si!}}}", "foo", &xi[0], &xi[1], "bar", "baz", "quux", &xi[2]);
	U("{\"foo\":{\"bar\":4}}", "{s?{s?i}}", "foo", "bar", &xi[0]);
	U("{\"foo\":{}}", "{s?{s?i}}", "foo", "bar", &xi[0]);
	U("{}", "{s?{s?i}}", "foo", "bar", &xi[0]);
	U("{\"foo\":42,\"baz\":45}", "{s?isi!}", "baz", &xi[0], "foo", &xi[1]);
	U("{\"foo\":42}", "{s?isi!}", "baz", &xi[0], "foo", &xi[1]);

	U("\"Pz8_Pz8_P2hlbGxvPj4-Pj4-Pg\"", "y", &xy[0], &xz[0]);
	U("\"\"", "y", &xy[0], &xz[0]);
	U("null", "y", &xy[0], &xz[0]);
	U("{\"foo\":\"Pz8_Pz8_P2hlbGxvPj4-Pj4-Pg\"}", "{s?y}", "foo", &xy[0], &xz[0]);
	U("{\"foo\":\"\"}", "{s?y}", "foo", &xy[0], &xz[0]);
	U("{}", "{s?y}", "foo", &xy[0], &xz[0]);

	c("null", "null", 1, 1);
	c("true", "true", 1, 1);
	c("false", "false", 1, 1);
	c("1", "1", 1, 1);
	c("1.0", "1.0", 1, 1);
	c("\"\"", "\"\"", 1, 1);
	c("\"hi\"", "\"hi\"", 1, 1);
	c("{}", "{}", 1, 1);
	c("{\"a\":true,\"b\":false}", "{\"b\":false,\"a\":true}", 1, 1);
	c("[]", "[]", 1, 1);
	c("[1,true,null]", "[1,true,null]", 1, 1);

	c("null", "true", 0, 0);
	c("null", "false", 0, 0);
	c("0", "1", 0, 0);
	c("1", "0", 0, 0);
	c("0", "true", 0, 0);
	c("0", "false", 0, 0);
	c("0", "null", 0, 0);

	c("\"hi\"", "\"hello\"", 0, 0);
	c("\"hello\"", "\"hi\"", 0, 0);

	c("{}", "null", 0, 0);
	c("{}", "true", 0, 0);
	c("{}", "1", 0, 0);
	c("{}", "1.0", 0, 0);
	c("{}", "[]", 0, 0);
	c("{}", "\"x\"", 0, 0);

	c("[1,true,null]", "[1,true]", 0, 1);
	c("{\"a\":true,\"b\":false}", "{\"a\":true}", 0, 1);
	c("{\"a\":true,\"b\":false}", "{\"a\":true,\"c\":false}", 0, 0);
	c("{\"a\":true,\"c\":false}", "{\"a\":true,\"b\":false}", 0, 0);

	return 0;
}
