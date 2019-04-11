#include <stdio.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

static int appmain(void *arg)
{
	const char *name = arg;
	char buffer[50];

	AFB_API_NOTICE(afbBindingV3root, "Entering Application main");
	printf("Hello, I'm %s!\n", name);
	printf("What's your name? ");
	scanf("%s", buffer);
	printf("Hi %s! Nice to meet you. OOOOPS I'm late bye bye\n", buffer);
	return 0;
}

static void application(int signum, void *arg)
{
	if (signum)
		exit(127);
	exit(appmain(arg));
}

int afbBindingV3entry(struct afb_api_x3 *rootapi)
{
	return afb_api_queue_job(rootapi, application, "BOB", NULL, 0);
}

