CC := gcc
CFLAGS := -Wall -Wextra
LDFLAGS := -lpcap

.PHONY: download extract_http all clean

all: download extract_http

download:
	curl -o data.bin https://challenge.i18.no/level/qrn8y39efltmdeyb60eivqttwlqn8gm2/data.bin

extract_http: download
	$(CC) $(CFLAGS) -o $@ extract_http.c $(LDFLAGS)

clean:
	-$(RM) -f extract_http
