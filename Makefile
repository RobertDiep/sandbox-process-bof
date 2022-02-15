CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip

CFLAGS = -Wno-multichar -masm=intel -Os

CFLAGS_64 = $(CFLAGS) -m64
STRIP_FLAGS =  --strip-unneeded 

LIBINCLUDE := 

BUILD_DIR := ./bin
TEST_DIR := ./tst
SRC_DIR := ./src

# collect all source files
SRC := $(wildcard $(SRC_DIR)/*.c)

# substitute names of .c files into x86/x64 .o files
OBJS64 := $(SRC:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.x64.o)
TEST64 := $(SRC:$(SRC_DIR)/%.c=$(TEST_DIR)/%.x64.exe)

.PHONY: all
all: 64bit

.PHONY: 64bit
64bit: $(OBJS64)

.PHONY: test
test: $(TEST64)

.PHONY: clean
clean:
	rm -f $(BUILD_DIR)/* $(TEST_DIR)/*

$(TEST_DIR)/%.x64.exe: $(SRC_DIR)/%.c
	$(CC_x64) $(LIBINCLUDE) $(CFLAGS_64) -o $@ $<
	$(STRIP_x64) $(STRIP_FLAGS) $@

$(BUILD_DIR)/%.x64.o: $(SRC_DIR)/%.c
	$(CC_x64) $(LIBINCLUDE) $(CFLAGS_64) -DBOF -c -o $@ $<
	$(STRIP_x64) $(STRIP_FLAGS) $@