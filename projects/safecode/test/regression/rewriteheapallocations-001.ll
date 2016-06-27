; RUN: clang -emit-llvm -S -c -fmemsafety -bbc %s -o /dev/null
define i32 @main(i32 %argc, i8** %argv) #0 {
entry:
  %0 = call i8* @malloc(i64 10)
  call void @free(i8* %0)
  %1 = call i8* @calloc(i64 10, i64 10)
  call void @free(i8* %1)
  %2 = call i8* @realloc(i8* %0, i64 10)
  call void @free(i8* %2)
  ret i32 0
}


declare i8* @malloc(i64)
declare i8* @calloc(i64, i64)
declare i8* @realloc(i8*, i64)
declare void @free(i8*)
