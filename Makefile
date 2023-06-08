all: server client miner

server:
	g++ -o ./build/server -I./block_chain -std=c++20 ./src/server.cpp ./block_chain/block_chain.cpp -lcrypto -g

client:
	g++ -o ./build/client -I./block_chain ./src/client.cpp ./block_chain/block_chain.cpp -lcrypto -g

miner:
	g++ -o ./build/miner -I./block_chain ./src/miner.cpp ./block_chain/block_chain.cpp -lcrypto -g

clear:
	rm ./build/server
	rm ./build/client
	rm ./build/miner