#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

#include <check.h>
#if !defined(ck_assert_ptr_null)
# define ck_assert_ptr_null(X)      ck_assert_ptr_eq(X, NULL)
# define ck_assert_ptr_nonnull(X)   ck_assert_ptr_ne(X, NULL)
#endif

#include "afb-api.h"
#include "afb-apiset.h"

const char *names[] = {
	"Sadie",
	"Milford",
	"Yvette",
	"Carma",
	"Cory",
	"Clarence",
	"Jeffery",
	"Molly",
	"Sheba",
	"Tasha",
	"Corey",
	"Gerry",
	NULL
};

const char *aliases[] = {
	"Rich",		"Molly",
	"Alicia",	"Carma",
	"Drema",	"YVETTE",
	"Pablo",	"Sheba",
	"Wendell",	"Sadie",
	"Cathrine",	"CarMa",
	"Allen",	"Corey",
	"Tori",		"Drema",
	NULL
};

const char *extras[] = {
	"Meta",
	"Delia",
	"Pearlie",
	"Hank",
	"Vena",
	"Terrance",
	"Gloria",
	"Tobi",
	"Mack",
	"Rosalee",
	NULL
};

struct afb_api_itf api_itf_null = {
	.call = NULL,
	.service_start = NULL,
#if WITH_AFB_HOOK
	.update_hooks = NULL,
#endif
	.get_logmask = NULL,
	.set_logmask = NULL,
	.describe = NULL,
	.unref = NULL
};


/*********************************************************************/
/* check the initialisation */
START_TEST (check_initialisation)
{
	const char name[] = "name";
	const char noname[] = "";
	int to = 3600;
	int noto = -1;
	struct afb_apiset *a, *b;

	a = afb_apiset_create(NULL, noto);
	ck_assert_ptr_nonnull(a);
	ck_assert_str_eq(noname, afb_apiset_name(a));
	ck_assert_int_eq(noto, afb_apiset_timeout_get(a));
	afb_apiset_timeout_set(a, to);
	ck_assert_int_eq(to, afb_apiset_timeout_get(a));
	b = afb_apiset_addref(a);
	ck_assert_ptr_eq(a, b);
	afb_apiset_unref(b);
	afb_apiset_unref(a);

	a = afb_apiset_create(name, to);
	ck_assert_ptr_nonnull(a);
	ck_assert_str_eq(name, afb_apiset_name(a));
	ck_assert_int_eq(to, afb_apiset_timeout_get(a));
	afb_apiset_timeout_set(a, noto);
	ck_assert_int_eq(noto, afb_apiset_timeout_get(a));
	b = afb_apiset_addref(a);
	ck_assert_ptr_eq(a, b);
	afb_apiset_unref(b);
	afb_apiset_unref(a);
}
END_TEST

/*********************************************************************/
/* check that NULL is a valid value for addref/unref */
START_TEST (check_sanity)
{
	struct afb_apiset *a;

	a = afb_apiset_addref(NULL);
	ck_assert_ptr_null(a);
	afb_apiset_unref(NULL);
	ck_assert(1);
}
END_TEST

/*********************************************************************/
/* check creation and retrieval of apis */

START_TEST (check_creation)
{
	int i, j, nn, na;
	struct afb_apiset *a;
	struct afb_api_item sa;
	const char *x, *y, **set;
	const struct afb_api_item *pa;

	/* create a apiset */
	a = afb_apiset_create(NULL, 0);
	ck_assert_ptr_nonnull(a);

	/* add apis */
	for (i = 0 ; names[i] != NULL ; i++) {
		sa.itf = &api_itf_null;
		sa.closure = (void*)names[i];
		sa.group = names[i];
		ck_assert_int_eq(0, afb_apiset_add(a, names[i], sa));
		pa = afb_apiset_lookup(a, names[i], 1);
		ck_assert_ptr_nonnull(pa);
		ck_assert_ptr_eq(sa.itf, pa->itf);
		ck_assert_ptr_eq(sa.closure, pa->closure);
		ck_assert_ptr_eq(sa.group, pa->group);
		ck_assert_int_eq(0, afb_apiset_is_alias(a, names[i]));
		ck_assert_str_eq(names[i], afb_apiset_unalias(a, names[i]));
		ck_assert_int_eq(-1, afb_apiset_add(a, names[i], sa));
		ck_assert_int_eq(errno, EEXIST);
	}
	nn = i;

	/* add aliases */
	for (i = 0 ; aliases[i] != NULL ; i += 2) {
		ck_assert_int_eq(-1, afb_apiset_add_alias(a, extras[0], aliases[i]));
		ck_assert_int_eq(errno, ENOENT);
		ck_assert_int_eq(0, afb_apiset_add_alias(a, aliases[i + 1], aliases[i]));
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, aliases[i], 1));
		ck_assert_int_eq(1, afb_apiset_is_alias(a, aliases[i]));
		x = afb_apiset_unalias(a, aliases[i]);
		y = afb_apiset_unalias(a, aliases[i + 1]);
		ck_assert_int_eq(0, strcasecmp(x, y));
		ck_assert_int_eq(-1, afb_apiset_add_alias(a, aliases[i + 1], aliases[i]));
		ck_assert_int_eq(errno, EEXIST);
	}
	na = i / 2;

	/* check extras */
	for (i = 0 ; extras[i] != NULL ; i++) {
		pa = afb_apiset_lookup(a, extras[i], 1);
		ck_assert_ptr_null(pa);
		ck_assert_int_eq(errno, ENOENT);
	}

	/* get the names */
	set = afb_apiset_get_names(a, 0, 1);
	ck_assert_ptr_nonnull(set);
	for (i = 0 ; set[i] != NULL ; i++) {
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[i], 0));
		ck_assert_int_eq(0, afb_apiset_is_alias(a, set[i]));
		if (i)
			ck_assert_int_gt(0, strcasecmp(set[i-1], set[i]));
	}
	ck_assert_int_eq(i, nn);
	free(set);
	set = afb_apiset_get_names(a, 0, 2);
	ck_assert_ptr_nonnull(set);
	for (i = 0 ; set[i] != NULL ; i++) {
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[i], 0));
		ck_assert_int_eq(1, afb_apiset_is_alias(a, set[i]));
		if (i)
			ck_assert_int_gt(0, strcasecmp(set[i-1], set[i]));
	}
	ck_assert_int_eq(i, na);
	free(set);
	set = afb_apiset_get_names(a, 0, 3);
	ck_assert_ptr_nonnull(set);
	for (i = 0 ; set[i] != NULL ; i++) {
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[i], 0));
		if (i)
			ck_assert_int_gt(0, strcasecmp(set[i-1], set[i]));
	}
	ck_assert_int_eq(i, nn + na);

	/* removes the apis to check deletion */
	for (i = 0 ; i < nn + na ; i++) {
		if (!set[i])
			continue;

		/* should be present */
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[i], 0));

		/* deleting a non aliased api removes the aliases! */
		if (!afb_apiset_is_alias(a, set[i])) {
			for (j = i + 1 ; j < nn + na ; j++) {
				if (!set[j])
					continue;
				ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[j], 0));
				if (afb_apiset_is_alias(a, set[j])
				 && afb_apiset_lookup(a, set[i], 0) == afb_apiset_lookup(a, set[j], 0)) {
					ck_assert(set[j][0] > 0);
					((char*)set[j])[0] = (char)-set[j][0];
				}
			}
		}

		/* delete now */
		ck_assert_int_eq(0, afb_apiset_del(a, set[i]));
		ck_assert_ptr_null(afb_apiset_lookup(a, set[i], 0));

		/* check other not removed except aliases */
		for (j = i + 1 ; j < nn + na ; j++) {
			if (!set[j])
				continue;
			if (set[j][0] > 0)
				ck_assert_ptr_nonnull(afb_apiset_lookup(a, set[j], 0));
			else {
				((char*)set[j])[0] = (char)-set[j][0];
				ck_assert_ptr_null(afb_apiset_lookup(a, set[j], 0));
				set[j] = NULL;
			}
		}
	}
	free(set);

	afb_apiset_unref(a);
}
END_TEST

/*********************************************************************/
/* check onlack behaviour */

int onlackcount;

static void onlackcleanup(void *closure)
{
	int *count = closure;
	ck_assert_ptr_eq(count, &onlackcount);
	*count = 0;
}
static int onlack(void *closure, struct afb_apiset *a, const char *name)
{
	int *count = closure;
	struct afb_api_item sa;

	ck_assert_ptr_eq(count, &onlackcount);
	(*count)++;

	sa.itf = &api_itf_null;
	sa.closure = (void*)name;
	sa.group = name;

	ck_assert_int_eq(0, afb_apiset_add(a, name, sa));
	return 1;
}

START_TEST (check_onlack)
{
	int i;
	struct afb_apiset *a;
	struct afb_api_item sa;
	const char *x, *y;
	const struct afb_api_item *pa;

	/* create a apiset */
	a = afb_apiset_create(NULL, 0);
	ck_assert_ptr_nonnull(a);

	/* add apis */
	for (i = 0 ; names[i] != NULL ; i++) {
		sa.itf = &api_itf_null;
		sa.closure = (void*)names[i];
		sa.group = names[i];
		ck_assert_int_eq(0, afb_apiset_add(a, names[i], sa));
		pa = afb_apiset_lookup(a, names[i], 1);
		ck_assert_ptr_nonnull(pa);
		ck_assert_ptr_eq(sa.itf, pa->itf);
		ck_assert_ptr_eq(sa.closure, pa->closure);
		ck_assert_ptr_eq(sa.group, pa->group);
		ck_assert_int_eq(0, afb_apiset_is_alias(a, names[i]));
		ck_assert_str_eq(names[i], afb_apiset_unalias(a, names[i]));
		ck_assert_int_eq(-1, afb_apiset_add(a, names[i], sa));
		ck_assert_int_eq(errno, EEXIST);
	}

	/* add aliases */
	for (i = 0 ; aliases[i] != NULL ; i += 2) {
		ck_assert_int_eq(-1, afb_apiset_add_alias(a, extras[0], aliases[i]));
		ck_assert_int_eq(errno, ENOENT);
		ck_assert_int_eq(0, afb_apiset_add_alias(a, aliases[i + 1], aliases[i]));
		ck_assert_ptr_nonnull(afb_apiset_lookup(a, aliases[i], 1));
		ck_assert_int_eq(1, afb_apiset_is_alias(a, aliases[i]));
		x = afb_apiset_unalias(a, aliases[i]);
		y = afb_apiset_unalias(a, aliases[i + 1]);
		ck_assert_int_eq(0, strcasecmp(x, y));
		ck_assert_int_eq(-1, afb_apiset_add_alias(a, aliases[i + 1], aliases[i]));
		ck_assert_int_eq(errno, EEXIST);
	}

	/* check extras */
	for (i = 0 ; extras[i] != NULL ; i++) {
		pa = afb_apiset_lookup(a, extras[i], 1);
		ck_assert_ptr_null(pa);
		ck_assert_int_eq(errno, ENOENT);
	}

	/* put the onlack feature */
	afb_apiset_onlack_set(a, onlack, &onlackcount, onlackcleanup);

	/* check extras */
	onlackcount = 0;
	for (i = 0 ; extras[i] != NULL ; i++) {
		ck_assert_int_eq(onlackcount, i);
		pa = afb_apiset_lookup(a, extras[i], 1);
		ck_assert_int_eq(onlackcount, i + 1);
		ck_assert_ptr_nonnull(pa);
		ck_assert_ptr_eq(&api_itf_null, pa->itf);
		ck_assert_ptr_eq(extras[i], pa->closure);
		ck_assert_ptr_eq(extras[i], pa->group);
	}

	ck_assert_int_eq(onlackcount, i);
	afb_apiset_unref(a);
	ck_assert_int_eq(onlackcount, 0);
}
END_TEST

/*********************************************************************/

struct set_api {
	const char *name;
	int init;
	int mask;
} set_apis[] = {
	{ "Sadie", 0, 0 },
	{ "Milford", 0, 0 },
	{ "Yvette", 0, 0 },
	{ "Carma", 0, 0 },
	{ "Cory", 0, 0 },
	{ "Clarence", 0, 0 },
	{ "Jeffery", 0, 0 },
	{ "Molly", 0, 0 },
	{ "Sheba", 0, 0 },
	{ "Tasha", 0, 0 },
	{ "Corey", 0, 0 },
	{ "Gerry", 0, 0 },
	{ NULL, 0, 0 }
};

int set_count;
struct set_api *set_last_api;

void set_cb0(void *closure)
{
	set_last_api = closure;
	set_count++;
}

void set_cb_setmask(void *closure, int mask)
{
	set_cb0(closure);
	set_last_api->mask = mask;
}

int set_cb_getmask(void *closure)
{
	set_cb0(closure);
	return set_last_api->mask;
}

int set_cb_start(void *closure)
{
	set_cb0(closure);
	ck_assert_int_eq(0, set_last_api->init);
	set_last_api->init = 1;
	return 0;
}

struct afb_api_itf set_api_itf = {
	.call = NULL,
	.service_start = set_cb_start,
#if WITH_AFB_HOOK
	.update_hooks = set_cb0,
#endif
	.get_logmask = set_cb_getmask,
	.set_logmask = set_cb_setmask,
	.describe = NULL,
	.unref = set_cb0
};

START_TEST (check_settings)
{
	int i, nn, mask;
	struct afb_apiset *a;
	struct afb_api_item sa;

	/* create a apiset */
	a = afb_apiset_create(NULL, 0);
	ck_assert_ptr_nonnull(a);

	/* add apis */
	for (i = 0 ; set_apis[i].name != NULL ; i++) {
		sa.itf = &set_api_itf;
		sa.closure = &set_apis[i];
		sa.group = NULL;
		ck_assert_int_eq(0, afb_apiset_add(a, set_apis[i].name, sa));
	}
	nn = i;

	set_count = 0;
	afb_apiset_start_all_services(a);
	ck_assert_int_eq(nn, set_count);

#if WITH_AFB_HOOK
	set_count = 0;
	afb_apiset_update_hooks(a, NULL);
	ck_assert_int_eq(nn, set_count);
#endif

	for (mask = 1 ; !(mask >> 10) ; mask <<= 1) {
		set_count = 0;
		afb_apiset_set_logmask(a, NULL, mask);
		ck_assert_int_eq(nn, set_count);
		set_count = 0;
		for (i = 0 ; set_apis[i].name != NULL ; i++) {
			ck_assert_int_eq(mask, afb_apiset_get_logmask(a, set_apis[i].name));
			ck_assert_ptr_eq(set_last_api, &set_apis[i]);
			ck_assert_int_eq(i + 1, set_count);
		}
	}

	set_count = 0;
	afb_apiset_unref(a);
	ck_assert_int_eq(nn, set_count);
}
END_TEST

/*********************************************************************/

struct clacl {
	const char *name;
	int count;
} clacl[] = {
	{ "Sadie", 0 },
	{ "Milford", 0 },
	{ "Yvette", 0 },
};

struct clapi {
	const char *name;
	const char *provides;
	const char *requires;
	const char *apireq;
	int init;
	int expect;
} clapi[] = {
	{ "Carma", "", "Sadie", "", 0, 9 },
	{ "Cory", "Milford", "", "Clarence", 0, 3 },
	{ "Clarence", "Milford", "", "Jeffery", 0, 2 },
	{ "Jeffery", "Milford", "", "", 0, 1 },
	{ "Molly", "Yvette", "", "Corey", 0, 6 },
	{ "Sheba", "Yvette", "Milford", "Molly", 0, 7 },
	{ "Tasha", "Sadie", "Yvette", "", 0, 8 },
	{ "Corey", "Sadie", "Milford", "Gerry", 0, 5 },
	{ "Gerry", "Sadie", "Milford", "", 0, 4 },
	{ NULL, NULL, NULL, NULL, 0, 0 }
};

int clorder;

int clacb_start(void *closure)
{
	struct clapi *a = closure;
	int i;

	ck_assert_int_eq(0, a->init);

	for (i = 0 ; clapi[i].name ; i++) {
		if (a->requires && a->requires[0]
		&& clapi[i].provides && clapi[i].provides[0]
		&& !strcmp(a->requires, clapi[i].provides))
			ck_assert_int_ne(0, clapi[i].init);
		if (a->apireq && a->apireq[0]
		&& !strcmp(a->apireq, clapi[i].name))
			ck_assert_int_ne(0, clapi[i].init);
	}
	a->init = ++clorder;
	ck_assert_int_eq(a->init, a->expect);

	return 0;
}

struct afb_api_itf clitf = {
	.call = NULL,
	.service_start = clacb_start,
#if WITH_AFB_HOOK
	.update_hooks = NULL,
#endif
	.get_logmask = NULL,
	.set_logmask = NULL,
	.describe = NULL,
	.unref = NULL
};

START_TEST (check_classes)
{
	int i;
	struct afb_apiset *a;
	struct afb_api_item sa;

	/* create a apiset */
	a = afb_apiset_create(NULL, 0);
	ck_assert_ptr_nonnull(a);

	/* add apis */
	for (i = 0 ; clapi[i].name != NULL ; i++) {
		sa.itf = &clitf;
		sa.closure = &clapi[i];
		sa.group = NULL;
		ck_assert_int_eq(0, afb_apiset_add(a, clapi[i].name, sa));
	}

	/* add constraints */
	for (i = 0 ; clapi[i].name != NULL ; i++) {
		if (clapi[i].provides && clapi[i].provides[0])
			ck_assert_int_eq(0, afb_apiset_provide_class(a, clapi[i].name, clapi[i].provides));
		if (clapi[i].requires && clapi[i].requires[0])
			ck_assert_int_eq(0, afb_apiset_require_class(a, clapi[i].name, clapi[i].requires));
		if (clapi[i].apireq && clapi[i].apireq[0])
			ck_assert_int_eq(0, afb_apiset_require(a, clapi[i].name, clapi[i].apireq));
	}

	/* start all */
	ck_assert_int_eq(0, afb_apiset_start_all_services(a));

	afb_apiset_unref(a);
}
END_TEST

/*********************************************************************/

START_TEST (check_subset)
{
	int rc;
	struct afb_apiset *a, *b, *c, *d;

	a = afb_apiset_create_subset_first(NULL, "a", 0);
	ck_assert_ptr_nonnull(a);
	ck_assert_str_eq("a", afb_apiset_name(a));
	ck_assert_ptr_null(afb_apiset_subset_get(a));

	b = afb_apiset_create_subset_first(a, "b", 0);
	ck_assert_ptr_nonnull(b);
	ck_assert_str_eq("b", afb_apiset_name(b));
	ck_assert_ptr_eq(b, afb_apiset_subset_get(a));
	ck_assert_ptr_null(afb_apiset_subset_get(b));

	c = afb_apiset_create_subset_first(a, "c", 0);
	ck_assert_ptr_nonnull(c);
	ck_assert_str_eq("c", afb_apiset_name(c));
	ck_assert_ptr_eq(c, afb_apiset_subset_get(a));
	ck_assert_ptr_eq(b, afb_apiset_subset_get(c));
	ck_assert_ptr_null(afb_apiset_subset_get(b));

	d = afb_apiset_create_subset_last(a, "d", 0);
	ck_assert_ptr_nonnull(d);
	ck_assert_str_eq("d", afb_apiset_name(d));
	ck_assert_ptr_eq(c, afb_apiset_subset_get(a));
	ck_assert_ptr_eq(b, afb_apiset_subset_get(c));
	ck_assert_ptr_eq(d, afb_apiset_subset_get(b));
	ck_assert_ptr_null(afb_apiset_subset_get(d));

	rc = afb_apiset_subset_set(a, b);
	ck_assert(rc == 0);
	ck_assert_ptr_eq(b, afb_apiset_subset_get(a));
	ck_assert_ptr_eq(d, afb_apiset_subset_get(b));
	ck_assert_ptr_null(afb_apiset_subset_get(d));

	afb_apiset_unref(a);
}
END_TEST

/*********************************************************************/

static Suite *suite;
static TCase *tcase;

void mksuite(const char *name) { suite = suite_create(name); }
void addtcase(const char *name) { tcase = tcase_create(name); suite_add_tcase(suite, tcase); }
void addtest(TFun fun) { tcase_add_test(tcase, fun); }
int srun()
{
	int nerr;
	SRunner *srunner = srunner_create(suite);
	srunner_run_all(srunner, CK_NORMAL);
	nerr = srunner_ntests_failed(srunner);
	srunner_free(srunner);
	return nerr;
}

int main(int ac, char **av)
{
	mksuite("apiset");
		addtcase("apiset");
			addtest(check_initialisation);
			addtest(check_sanity);
			addtest(check_creation);
			addtest(check_onlack);
			addtest(check_settings);
			addtest(check_classes);
			addtest(check_subset);
	return !!srun();
}
