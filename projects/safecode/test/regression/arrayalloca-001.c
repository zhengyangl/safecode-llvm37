// RUN: test.sh -e -s "@malloc" -t %t %s
//
// TEST: arrayalloca-001
//
// Description:
//  Test PromoteArrayAllocas pass
//

int
main (int argc, char ** argv){
  int a[argc];
  return (int)a;
}
