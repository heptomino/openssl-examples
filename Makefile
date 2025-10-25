CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS := -lssl -lcrypto

SRC_DIR := examples
BIN_DIR := bin

SERVER_SRC := $(SRC_DIR)/server.cpp
SERVER_BIN := $(BIN_DIR)/server

.PHONY: all clean
all: $(SERVER_BIN)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(SERVER_BIN): | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER_BIN) $(LDFLAGS)

clean:
	rm -f $(SERVER_BIN)
