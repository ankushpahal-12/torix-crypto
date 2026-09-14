# TORIX Makefile
CC ?= gcc
CFLAGS ?= -O3 -std=c99 -mavx2 -Wall -Wextra -pedantic -Isrc

SRC = src/h512.c src/h512_cli.c
TARGET = torix_engine

ifeq ($(OS),Windows_NT)
    TARGET := torix_engine.exe
    RM := del /Q /F
else
    RM := rm -f
endif

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	@echo "[BUILD SUCCESS] $(TARGET) compiled successfully."

shared:
	$(CC) $(CFLAGS) -shared src/h512.c -o libtorix.dll

test:
	python tests/run_all_phases.py

clean:
	-$(RM) $(TARGET) *.dll *.so *.o
