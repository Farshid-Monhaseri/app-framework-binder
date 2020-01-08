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

/**
 * records path to the expanded node
 */
struct path
{
	struct json_object *object;	/**< node being expanded */
	struct path *upper;		/**< link to upper expanded nodes */
};

/**
 * root of the JSON being parsed
 */
struct json_object *root;

/**
 * Search for a reference of type "#/a/b/c" int the
 * parsed JSON object
 */
struct json_object *search(const char *path)
{
	char *d;
	struct json_object *i;

	/* does it match #/ at the beginning? */
	if (path[0] != '#' || (path[0] && path[1] != '/'))
		return NULL;

	/* search from root to target */
	i = root;
	d = strdupa(path+2);
	d = strtok(d, "/");
	while(i && d) {
		if (!json_object_object_get_ex(i, d, &i))
			return NULL;
		d = strtok(NULL, "/");
	}
	return i;
}

/**
 * Expands the node designated by path and returns its expanded form
 */
struct json_object *expand(struct path path)
{
	struct path *p;
	struct json_object *o, *x;
	int n, i;
	struct json_object_iterator ji, jn;

	/* expansion depends of the type of the node */
	switch (json_object_get_type(path.object)) {
	case json_type_object:
		/* for object, look if it contains a property "$ref" */
		if (json_object_object_get_ex(path.object, "$ref", &o)) {
			/* yes, reference, try to substitute its target */
			if (!json_object_is_type(o, json_type_string)) {
				fprintf(stderr, "found a $ref not being string. Is: %s\n", json_object_get_string(o));
				exit(1);
			}
			x = search(json_object_get_string(o));
			if (!x) {
				fprintf(stderr, "$ref not found. Was: %s\n", json_object_get_string(o));
				exit(1);
			}
			p = &path;
			while(p) {
				if (x == p->object) {
					fprintf(stderr, "$ref recursive. Was: %s\n", json_object_get_string(o));
					exit(1);
				}
				p = p->upper;
			}
			/* cool found, return a new instance of the target */
			return json_object_get(x);
		}
		/* no, expand the values */
		ji = json_object_iter_begin(path.object);
		jn = json_object_iter_end(path.object);
		while (!json_object_iter_equal(&ji, &jn)) {
			o = json_object_iter_peek_value(&ji);
			x = expand((struct path){ .object = o, .upper = &path });
			if (x != o)
				json_object_object_add(path.object, json_object_iter_peek_name(&ji), x);
			json_object_iter_next(&ji);
		}
		break;
	case json_type_array:
		/* expand the values of arrays */
		i = 0;
		n = (int)json_object_array_length(path.object);
		while (i != n) {
			o = json_object_array_get_idx(path.object, i);
			x = expand((struct path){ .object = o, .upper = &path });
			if (x != o)
				json_object_array_put_idx(path.object, i, x);
			i++;
		}
		break;
	default:
		/* otherwise no expansion */
		break;
	}
	/* return the given node */
	return path.object;
}

/**
 * process a file and prints its expansion on stdout
 */
void process(char *filename)
{
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

	/* expand */
	root = expand((struct path){ .object = root, .upper = NULL });

	/* print the result */
	json_object_to_file_ext ("/dev/stdout", root, JSON_C_TO_STRING_PRETTY);

	/* clean up */
	json_object_put(root);
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

