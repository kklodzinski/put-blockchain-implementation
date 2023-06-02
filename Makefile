all: server client

server:
	g++ -o ./build/server -I./block_chain ./src/server.cpp ./block_chain/block_chain.cpp -lcrypto -g

client:
	g++ -o ./build/client -I./block_chain ./src/client.cpp ./block_chain/block_chain.cpp -lcrypto -g

clear:
	rm ./build/server
	rm ./build/client