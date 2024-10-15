CC = clang
CFLAGS = -O2 -Wall -target bpf -c
LIBS = -lbpf -lelf -lz -lcjson

all: xdp_firewall.o user_space

xdp_firewall.o: xdp_firewall.c include/common.h include/rules.h include/filters.h
	$(CC) $(CFLAGS) xdp_firewall.c -o xdp_firewall.o

user_space: user_space.c manage_rules.c manage_filters.c traffic_logger.c log_manager.c include/common.h include/rules.h include/filters.h
	gcc -o shield user_space.c manage_rules.c manage_filters.c traffic_logger.c log_manager.c $(LIBS)

clean:
	rm -f *.o shield
