// RUN: test.sh -e -s "@malloc" -t %t %s
//
// TEST: arrayalloca-002
//
// Description:
//  Test if PromoteArrayAllocas pass transform array allocas which are not
//  in entry blocks correctly.
//

int
main (int argc, char ** argv){
  int *p = 0;
  if(argc)
  {
    int a[argc];
    p = a;
  }
  return (int)p;
}
