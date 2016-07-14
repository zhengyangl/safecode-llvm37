// RUN: test.sh -p -s "pchk_getActualValue" -t %t %s
//
// TEST: insertgetactualvaluebeforegep-001 
//
// Description:
//  Test if RewriteOOB pass insert a pchk_getActualValue before GEP instruction.
//
static char *find_end_of_line(char *scan) {
  while (*(++scan) != '\n');
  return scan;
}

int main() {
  char *p = find_end_of_line("abc\ndef");
  return (int)p;
}

