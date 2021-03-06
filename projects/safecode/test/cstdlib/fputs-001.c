// RUN: test.sh -e -t %t %s
//
// No fmemopen() on darwin.
// XFAIL: darwin

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// fputs() reading past the end of the input string.

int main()
{
  char buf[1024];
  char str[100];
  FILE *f;

  memset(str, 'a', 100);

  f = fmemopen(buf, sizeof(buf), "r+");
  fputs(str, f);
  fclose(f);

  return 0;
}
