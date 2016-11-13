#include <stdio.h>
#include <stdlib.h>

int main(void) {
  char c;

  int *ptr = malloc(1024);

  c = fgetc(stdin);

  printf("%c\n", c);

  if (c == '0')
    free(ptr);

  ptr[1] = 0xaBad1dea;
}
