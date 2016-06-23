// RUN: test.sh -p -s "@malloc" -t %t %s 
//
// TEST: arrayalloca-002
//
// Description:
//  Test if PromoteArrayAllocas pass transform array allocas which are not
//  in entry blocks correctly.
//

int
get_size (){
  return 4;
}

int
main (int argc, char ** argv){
  int *p = 0;
  if(argc)
  {
    int a[get_size()];
    p = a;
  }
  return *p;
}
