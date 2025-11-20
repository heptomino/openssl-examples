CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS := -lssl -lcrypto

SRC_DIR := examples
BIN_DIR := bin

# Automatically detect all .cpp files in SRC_DIR
SOURCES := $(wildcard $(SRC_DIR)/*.cpp)
BINS := $(patsubst $(SRC_DIR)/%.cpp,$(BIN_DIR)/%,$(SOURCES))

.PHONY: all clean rebuild

# Default target builds all binaries
all: $(BINS)

# Rule to build each binary
$(BIN_DIR)/%: $(SRC_DIR)/%.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Ensure BIN_DIR exists
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean all binaries and logs
clean:
	rm -rf $(BIN_DIR)/* logs/*

# Rebuild everything from scratch
rebuild: clean all
