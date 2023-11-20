Emily Cory

To run standalone code:
	compile with 
	gcc -g -o compdetect compdetect.c cJSON/cJSON.c -lm

	cJSON is a JSON parser in C written by Dave Gamble. I used
	his parser to parse the json file that is needed in calling
	the function.

	now, to run the code, I run it with 
	sudo ./compdetect myconfig.json

	myconfig.json holds the necessary information to run the 
	code. It will be included in the .zip file.

	a file called random_file is also necessary to run the code. 
	It is a file full of high entropy characters.
