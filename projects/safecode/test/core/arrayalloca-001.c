// RUN: test.sh -p -s "@malloc" -t %t %s 
//
// TEST: arrayalloca-001
//
// Description:
//  Test PromoteArrayAllocas pass
//

int
get_size (){
  return 4;
}

int
main (){
  int a[get_size()];
  return a[3];
}
