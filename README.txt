Emily Cory

To run the client/server application:
	compile the client with
	gcc -g -o client client.c cJSON/cJSON.c -lm
	
	cJSON is a JSON parser in C written by Dave Gamble. I used
	his parser to parse the json file that is needed in calling
	the function.

	compile the server with 
	gcc -g -o server server.c
	
	run the server first with the port number in the config file
	./server 7777
	
	run the client after the server with the config file
	./client myconfig.json
	
	myconfig.json holds the necessary information to run the 
	code. It will be included in the .zip file.
	
	a file called random_file is also necessary to run the code. 
	It is a file full of high entropy characters.
