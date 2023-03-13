
SERVER = tcp_server

CLIENT = tcp_client

all: $(SERVER) $(CLIENT)

$(SERVER): tcp_server.cpp
	g++ tcp_server.cpp -o $@

$(CLIENT): tcp_client.cpp
	g++ tcp_client.cpp -o $@

clean:
	rm -f $(SERVER)
	rm -f $(CLIENT)