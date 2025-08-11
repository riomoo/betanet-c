CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g
LDFLAGS = -lssl -lcrypto -lpthread

# Source files
SOURCES = htx_simple.c
OBJECTS = $(SOURCES:.c=.o)

# Target executable
TARGET = htx_simple

# Default target
all: $(TARGET)

# Build executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Build object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libssl-dev build-essential

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-rpm:
	sudo dnf install -y openssl-devel gcc make

# Run client test
test-client: $(TARGET)
	./$(TARGET) client localhost 8080

# Run server test
test-server: $(TARGET)
	./$(TARGET) server 8080

# Debug build
debug: CFLAGS += -DDEBUG -g3
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: $(TARGET)

.PHONY: all clean install-deps install-deps-rpm test-client test-server debug release
