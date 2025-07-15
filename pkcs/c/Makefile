SRC_DIR = ./src
BUILD_DIR = ./build
PRIMUS_HOME = /usr/local/primus

CC = gcc
CPP = g++
CFLAGS = -Wall
INCFLAGS = -I $(PRIMUS_HOME)/include/ -I /usr/include/botan-2
LDFLAGS = -L $(PRIMUS_HOME)/lib/
LIBS = -l primusP11 -l botan-2

COMMON = src/primus_common.c

BINS = attestation rsa

all: $(BINS)

# https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
%: src/%.c $(COMMON)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCFLAGS) $^ $(LDFLAGS) $(LIBS) -o $(BUILD_DIR)/$@

%: src/%.cpp $(COMMON)
	mkdir -p $(BUILD_DIR)
	$(CPP) $(CFLAGS) $(INCFLAGS) $^ $(LDFLAGS) $(LIBS) -o $(BUILD_DIR)/$@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
