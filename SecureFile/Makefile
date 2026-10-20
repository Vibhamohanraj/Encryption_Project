# SecureFile — Makefile for Windows MSYS2 UCRT64
CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -O2 -Iinclude
LDFLAGS ?=

# Obtain OpenSSL and libsodium flags via pkg-config
PKG_CFLAGS := $(shell pkg-config --cflags openssl libsodium 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs openssl libsodium 2>/dev/null)

ifeq ($(strip $(PKG_LIBS)),)
    # Fallback if pkg-config is not in PATH
    PKG_LIBS := -lssl -lcrypto -lsodium
endif

CFLAGS += $(PKG_CFLAGS)
LIBS := $(PKG_LIBS)

SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
TEST_DIR := tests

SOURCES := $(SRC_DIR)/format.c \
           $(SRC_DIR)/kdf.c \
           $(SRC_DIR)/crypto.c \
           $(SRC_DIR)/file_handler.c \
           $(SRC_DIR)/password.c \
           $(SRC_DIR)/utils.c

OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES))

APP_TARGET := $(BUILD_DIR)/securefile.exe
TEST_TARGET := $(BUILD_DIR)/test_runner.exe

.PHONY: all clean test

all: $(APP_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(APP_TARGET): $(OBJECTS) $(BUILD_DIR)/main.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_main.o: $(TEST_DIR)/test_main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(TEST_TARGET): $(OBJECTS) $(BUILD_DIR)/test_main.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(LDFLAGS)

test: $(TEST_TARGET)
	@echo Running SecureFile automated verification suite...
	@$(TEST_TARGET)

clean:
	-rm -f $(BUILD_DIR)/*.o $(APP_TARGET) $(TEST_TARGET)
