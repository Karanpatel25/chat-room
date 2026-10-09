CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?=
SRCDIR  = src
SRCS    = main.c server.c chat.c http.c ws.c json.c auth.c store.c ratelimit.c util.c sha1.c sha256.c base64.c
OBJS    = $(addprefix build/,$(SRCS:.c=.o))
TARGET  = chat_server

.PHONY: all debug test test-frontend clean run
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

build/%.o: $(SRCDIR)/%.c $(wildcard $(SRCDIR)/*.h) | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# AddressSanitizer + UBSan build
debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined"

# Unit tests (crypto, JSON, WebSocket framing) + end-to-end test against a live server
test: $(TARGET) build/unit_tests
	./build/unit_tests
	python3 tests/e2e_test.py

# Frontend logic test (needs Node.js and `npm i jsdom`)
test-frontend:
	node tests/frontend_smoke.js

build/unit_tests: tests/unit_tests.c $(filter-out build/main.o build/server.o build/chat.o build/http.o,$(OBJS)) | build
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ tests/unit_tests.c $(filter-out build/main.o build/server.o build/chat.o build/http.o,$(OBJS)) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf build $(TARGET)
