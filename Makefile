CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -pthread
TARGET  := server
TEST_BIN := tests/test_router_ids

.PHONY: all test clean

all: $(TARGET)

$(TARGET): main.c func.c header.h
	$(CC) $(CFLAGS) main.c func.c -o $(TARGET)

$(TEST_BIN): tests/test_router_ids.c func.c header.h
	$(CC) $(CFLAGS) tests/test_router_ids.c func.c -o $(TEST_BIN)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f $(TARGET) $(TEST_BIN) *.o
