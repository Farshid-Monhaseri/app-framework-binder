/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * This simple program expands the object { "$ref": "#/path/to/a/target" }
 *
 * For example:
 *
 *  {
 *    "type":{
 *      "a": "int",
 *      "b": { "$ref": "#/type/a" }
 *    }
 *  }
 *
 * will be exapanded to
 *
 *  {
 *    "type":{
 *      "a": "int",
 *      "b": "int"
 *    }
 *  }
 *
 * Invocation:   program  [file|-]...
 *
 * without arguments, it reads the input.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <json-c/json.h>

#define oom(x) do{if(!(x)){fprintf(stderr,"out of memory\n");exit(1);}}while(0)

/**
 * root of the JSON being parsed
 */
struct json_object *root = NULL;

char *make_desc(struct json_object *o)
{
	const char *a, *b;
	char *desc, c, buf[3];
	size_t len;
	int i, pos, e;

	a = b = json_object_to_json_string_ext(root, 0);
	len = 1;
	while((c = *b++)) {
		len += 1 + ('"' == c);
	}

	len += 7 * (1 + len / 72);
	desc = malloc(len);
	oom(desc);

	len = pos = 0;
	b = a;
	while((c = *b++)) {
		if (c == '"') {
			buf[0] = '\\';
			buf[1] = '"';
			buf[2] = 0;
		}
		else if (c == '\\') {
			switch ((c = *b++)) {
			case '/':
				buf[0] = '/';
				buf[1] = 0;
				break;
			case 0:
				b--;
				/*@fallthrough@*/
			default:
				buf[0] = '\\';
				buf[1] = c;
				buf[2] = 0;
				break;
			}
		}
		else {
			buf[0] = c;
			buf[1] = 0;
		}
		i = e = 0;
		while (buf[i]) {
			if (pos >= 77 && !e) {
				desc[len++] = '"';
				desc[len++] = '\n';
				pos = 0;
			}
			if (pos == 0) {
				desc[len++] = ' ';
				desc[len++] = ' ';
				desc[len++] = ' ';
				desc[len++] = ' ';
				desc[len++] = '"';
				pos = 5;
			}
			c = buf[i++];
			desc[len++] = c;
			e = !e && c == '\\';
			pos++;
		}
	}
	desc[len++] = '"';
	desc[len++] = '\n';
	desc[len] = 0;
	return desc;
}

/**
 * process a file and prints its expansion on stdout
 */
void process(char *filename)
{
	char *desc;

	/* translate - */
	if (!strcmp(filename, "-"))
		filename = "/dev/stdin";

	/* check access */
	if (access(filename, R_OK)) {
		fprintf(stderr, "can't access file %s\n", filename);
		exit(1);
	}

	/* read the file */
	root = json_object_from_file(filename);
	if (!root) {
		fprintf(stderr, "reading file %s produced null\n", filename);
		exit(1);
	}

	/* create the description */
	desc = make_desc(root);

	printf("%s", desc);

	/* clean up */
	json_object_put(root);
	free(desc);
}

/** process the list of files or stdin if none */
int main(int ac, char **av)
{
	if (!*++av)
		process("-");
	else {
		do { process(*av); } while(*++av);
	}
	return 0;
}


