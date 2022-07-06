OBJ_NAME=main
MAIN_FILE=main.c
EXTRA_FILES=""
gcc -std=c11 -Wall -Iinclude -g -o bin/$OBJ_NAME $MAIN_FILE $EXTRA_FILES
