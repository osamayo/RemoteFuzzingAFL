#include <stdio.h>
#include <time.h>

int main()
{
	time_t t;
	t = time(NULL);
	printf("%d\n", t);


	return 0;
}
