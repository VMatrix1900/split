tcp: tcp_server.c
	gcc -Wall -g -o tcp tcp_server.c -levent

server: normal_serv.c
	gcc -Wall -g -o normal_serv normal_serv.c -lssl -lcrypto

client: cli.c
	gcc -Wall -g -o cli cli.c -lssl -lcrypto -lpthread

socket: socket.c
	gcc -Wall -g -o socket socket.c -levent -lpthread

bufsocket: bufferevent_socket.c
	gcc -Wall -g -o bufsocket bufferevent_socket.c -levent -lpthread

mem: bio_mem.c
	gcc -Wall -g -o mem bio_mem.c -lssl -lcrypto -lpthread

run_mem: mem
	./mem

seperate: client server socket
	./normal_serv &
	./cli &
	./socket

test_sem: test_sem.c test_sem_cli.c
	gcc -o sem_server test_sem.c -lpthread
	gcc -o sem_client test_sem_cli.c -lpthread
	./sem_server &
	./sem_client

run_server: server
	./normal_serv

run_client: client
	./cli

run_socket: socket
	./socket
