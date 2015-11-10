CC=clang++
CFLAGS=-c -O3 -std=c++11
LDFLAGS=-lssl -lcrypto -lcryptopp -lpthread -lmpg123 -lao
SOURCES=main.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=zad2

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
