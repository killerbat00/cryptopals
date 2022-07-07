OBJ_NAME=setOne
MAIN_FILE=setOne.c
EXTRA_FILES="include/hex.c include/b64.c include/xor.c"
gcc -std=c11 -Wall -Iinclude -g -o bin/$OBJ_NAME $MAIN_FILE $EXTRA_FILES
#valgrind --leak-check=yes --track-origins=yes -s --log-file=valgrind.rpt ./bin/$OBJ_NAME
