#include <stdio.h>


void load_pub_key(char* filename)
{
	
	FILE* fp = fopen(filename, "r");
	if (fp == NULL)
	{
		printf("file not found");
	}
	else
	{
		printf("success");
	}
}

int main()
{
	load_pub_key("../keys/ca_public_key.bin");	
	return 0;
}
