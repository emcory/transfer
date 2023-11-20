#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#define BUF_SIZE 500

typedef struct {
    char server_ip_address[16]; // IPv4 addresses can have a maximum of 15 characters
    int source_port_udp;
    int destination_port_udp;
    int destination_port_tcp_head_syn;
    int destination_port_tcp_tail_syn;
    int port_tcp_pre_probing;
    int port_tcp_post_probing;
    int udp_payload_size;
    int inter_measurement_time;
    int num_udp_packets_in_train;
    int udp_ttl;
} Config;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>. default for client is 7777\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int tcp_port = atoi(argv[1]);

    //create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    //make server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(tcp_port);

    //bind the socket
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    //listen for client
    listen(sockfd, 5);
    printf("Server listening on port %d\n", tcp_port);

    int client_sockfd;
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    
    //accept a new connection
    client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
    if (client_sockfd < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    //receive config info
    Config config;
    int success = recv(client_sockfd, (char*)&config, sizeof(config), 0);
    if (success < 0) {
        perror("Error receiving configuration file information\n");
        exit(1);
    }
    printf("Configuration file contents successfully received\n");
    
    //release successful tcp connection
    close(client_sockfd);

    //create udp socket
    client_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    //configure udp server socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.destination_port_udp);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    //bind the sockets
    if (bind(client_sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    struct pollfd timer = {
    	.fd = client_sockfd,
    	.events = POLLIN,
    	.revents = 0
    };

    struct timespec start_time_low, end_time_low;
    struct timespec start_time_high, end_time_high;

    char *packet = (char *) calloc(config.udp_payload_size, sizeof(char));
    //uint16_t *packet_id = (uint16_t*) packet;
    int expected = config.num_udp_packets_in_train;

    //low entropy
    int packets_received = 0; 
    int num_bytes_received;
    int timeout = 0;
    poll(&timer, 1, -1); 
    clock_gettime(CLOCK_REALTIME, &start_time_low);     
    
    while (packets_received < expected && poll(&timer, 1, 1000)) {
        //receive packets
        num_bytes_received = recvfrom(client_sockfd, packet, config.udp_payload_size, 0, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (num_bytes_received == -1) {
            perror("Packet receiving failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        packets_received++;
    }
    clock_gettime(CLOCK_REALTIME, &end_time_low); 

    if (packets_received < expected) {
    	timeout = 1;
    }    
    
    double elapsed_time_low_entropy = (end_time_low.tv_sec - start_time_low.tv_sec) + (end_time_low.tv_nsec - start_time_low.tv_nsec) / 1.0e9;

    //if the while loop hits the timeout, subtract the timeout time
    if (timeout == 1) {
    	elapsed_time_low_entropy -= 1;
    	double average_per_packet_low = elapsed_time_low_entropy / packets_received;
    	elapsed_time_low_entropy = average_per_packet_low * expected;
    }
    printf("Time between first and last packet: %.6f seconds\n", elapsed_time_low_entropy);

    //high entropy 
    timeout = 0;
    packets_received = 0;
    poll(&timer, 1, -1); 
    clock_gettime(CLOCK_REALTIME, &start_time_high);
    while (packets_received < expected && poll(&timer, 1, 1000)) {
	    num_bytes_received = recvfrom(client_sockfd, packet, config.udp_payload_size, 0, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
	    if (num_bytes_received == -1) {
	        perror("Packet receiving failed");
	        close(sockfd);
	        exit(EXIT_FAILURE);
	    }
	    packets_received++;
    }
    clock_gettime(CLOCK_REALTIME, &end_time_high);

	double elapsed_time_high_entropy = (end_time_high.tv_sec - start_time_high.tv_sec) + (end_time_high.tv_nsec - start_time_high.tv_nsec) / 1.0e9;

    //check if there is a timeout
    if (packets_received < expected) {
    	timeout = 1;
    }
    //if there is a timeout subtract timeout time
    if (timeout == 1) {
    	elapsed_time_high_entropy -= 1;
		double average_per_packet_high = elapsed_time_high_entropy / packets_received; 
		elapsed_time_high_entropy = average_per_packet_high * expected;   
    }

    printf("Time between first and last packet: %.6f seconds\n", elapsed_time_high_entropy);

    close(client_sockfd);
    free(packet);

    //compare (subtract (high ent per packet *6000) - (low ent per packet*6000)) it with the low entropy single packet, 
    //then do the calculation

	double time_difference;

	if (timeout == 1) {
		//compare
	} else {
	    //compare ∆tH - ∆tL with the threshold τ (100 ms)
	    time_difference = elapsed_time_high_entropy - elapsed_time_low_entropy;
	}

    //should not have compression
    char compression[100];
    if (time_difference > 0.1) {
        printf("Compression detected!\n");
        snprintf(compression, sizeof(compression), "Compression detected!");
        
    } else {
        printf("No compression was detected.\n");
        snprintf(compression, sizeof(compression), "No compression was detected.");
    }

    compression[strlen(compression)] = '\0';

    //tcp connection
    //create socket
    int post_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (post_sockfd == -1) {
        perror("Post probing socket creation failed");
        exit(EXIT_FAILURE);
    }

    //change port
    server_addr.sin_port = htons(config.port_tcp_post_probing);

    //bind the socket
    if (bind(post_sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Post probing binding failed");
        exit(EXIT_FAILURE);
    }

    //listen for client on new port
    listen(post_sockfd, 5);
    
    //accept a new connection
    client_sockfd = accept(post_sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
    if (client_sockfd < 0) {
        perror("Post probing accept failed");
        exit(EXIT_FAILURE);
    }

    send(client_sockfd, compression, strlen(compression) + 1, 0);
    printf("Compression results sent to client\n");

    close(client_sockfd);
}
