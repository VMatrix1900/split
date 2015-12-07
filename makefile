tcp: tcp_server.c
	gcc -Wall -g -o tcp tcp_server.c -levent

normal_server: normal_serv.c
	gcc -Wall -g -o normal_serv normal_serv.c -lssl -lcrypto

server: serv.c
	gcc -Wall -g -o serv serv.c -lssl -lcrypto -lpthread

client: cli.c
	gcc -Wall -g -o cli cli.c -lssl -lcrypto -lpthread

serv_socket: serv_socket.c
	gcc -Wall -g -o serv_socket serv_socket.c -levent -lpthread

cli_socket: cli_socket.c
	gcc -Wall -g -o cli_socket cli_socket.c -levent -lpthread

socket: serv_socket cli_socket

mem: bio_mem.c
	gcc -Wall -g -o mem bio_mem.c -lssl -lcrypto -lpthread

run_mem: mem
	./mem

test_sem: test_sem.c test_sem_cli.c
	gcc -o sem_server test_sem.c -lpthread
	gcc -o sem_client test_sem_cli.c -lpthread
	./sem_server &
	./sem_client

run_server: server
	./serv

run_client: client
	./cli

run_cli_socket: socket
	./cli_socket

run_serv_socket: socket
	./serv_socket
