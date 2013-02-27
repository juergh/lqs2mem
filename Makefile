BIN = lqs2mem

all:
	gcc -Wall -o $(BIN) $(BIN).c


clean:
	@rm *~ $(BIN) 2>/dev/null || true
