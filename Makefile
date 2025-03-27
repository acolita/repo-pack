# Makefile for repo-pack

# Compiler and flags
CC = gcc
CFLAGS ?= -Wall -Wextra -std=c11 -O2 -g
CPPFLAGS ?= -I./src
LDFLAGS ?= # Keep this to accept environment LDFLAGS like hardening options
LDLIBS = -lmagic -lcrypto # Specify libraries here

# Source files and target executable
SRC_DIR = src
SOURCES = $(SRC_DIR)/repo-pack.c
TARGET = repo-pack

# Default target
all: $(TARGET)

# Link the object files to create the executable
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $(TARGET) $(LDFLAGS) $(LDLIBS) # Add $(LDLIBS)

# Phony targets
.PHONY: all clean install uninstall check-deps

# Clean up build artifacts
clean:
	rm -f $(TARGET) *.o

# Install the executable - respects DESTDIR for packaging
install: $(TARGET)
	install -d $(DESTDIR)/usr/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/bin/

# Uninstall the executable
uninstall:
	rm -f $(DESTDIR)/usr/bin/$(TARGET)

# Check dependencies (useful for manual builds)
check-deps:
	@echo "Checking dependencies..."
	@if ! dpkg -s libmagic-dev > /dev/null 2>&1; then \
		echo "Error: libmagic-dev is not installed. Please run: sudo apt update && sudo apt install libmagic-dev"; \
		exit 1; \
	fi
	@if ! dpkg -s libssl-dev > /dev/null 2>&1; then \
		echo "Error: libssl-dev is not installed. Please run: sudo apt update && sudo apt install libssl-dev"; \
		exit 1; \
	fi
	@echo "Dependencies found."