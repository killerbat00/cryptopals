OBJ_NAME=main
MAIN_FILE=main.c
EXTRA_FILES=hex.c
gcc -std=c11 -Wall -Iinclude -o bin/$OBJ_NAME $MAIN_FILE $EXTRA_FILES
