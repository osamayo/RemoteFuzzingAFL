#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "getopt.h"

int one, two;
char* target;
void vuln()
{

	
	char input[100];
	if (one==1 && two==1)
	{
		FILE* fd = fopen(target, "r");
		if (fd==-1)
		{
			printf("failed to open file: %s", target);
			exit(EXIT_FAILURE);
		}
		fgets(input, 7, fd);
		if (strcmp(input, "hello\n") == 0)
		{
		
			fgets(input, 1000, fd);

		} else { puts("failed");}
		fclose(fd);

	} else 
	{
		puts("failed");
	}
	return;
}

int main(int argc, char** argv) 
{
	int c;
    while ((c = getopt(argc, argv, "t:cn")) != -1)
    {
        switch (c)
        {
            case 'n':
				one=1;
                break;
            case 'c':
				two=1;
                break;
            case 't':
				if (!optarg) {perror("No argument specified"); exit(EXIT_FAILURE);}
                target = optarg;

				break;
            default:
				exit(1);
        }
    }

	vuln();
	puts("worked!");

	return 0;
}
