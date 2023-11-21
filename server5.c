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

int create_and_bind(int tcp_port, int type, int protocol) {
    //create socket
    int sockfd = socket(AF_INET, type, protocol);
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

    return sockfd;
}

int connect_tcp(int tcp_port, int sockfd, int pre_or_post) {
	//listen for client
    listen(sockfd, 5);
    if (pre_or_post == 0) {
    	printf("Server listening on port %d\n", tcp_port);
    }

    int client_sockfd;
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    
    //accept a new connection
    client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
    if (client_sockfd < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    return client_sockfd;
}

Config receive_config(int client_sockfd) {
    //receive config info
    Config config;
    int success = recv(client_sockfd, (char*)&config, sizeof(config), 0);
    if (success < 0) {
        perror("Error receiving configuration file information\n");
        exit(1);
    }
    printf("Configuration file contents successfully received\n");

    return config;
}

int send_packets(Config config, struct pollfd timer, struct timespec *start_time, struct timespec *end_time, int udp_sockfd, double *elapsed_time) {
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);

    char *packet = (char *)calloc(config.udp_payload_size, sizeof(char));
    int expected = config.num_udp_packets_in_train;

    // low entropy
    int packets_received = 0;
    int num_bytes_received;
    int timeout = 0;
    poll(&timer, 1, -1); 
    clock_gettime(CLOCK_REALTIME, start_time);

    while (packets_received < expected && poll(&timer, 1, 1000)) {
        // receive packets
        num_bytes_received = recvfrom(udp_sockfd, packet, config.udp_payload_size, 0, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (num_bytes_received == -1) {
            perror("Packet receiving failed");
            close(udp_sockfd);
            exit(EXIT_FAILURE);
        }
        packets_received++;
    }
    clock_gettime(CLOCK_REALTIME, end_time);

    if (packets_received < expected) {
        timeout = 1;
    }

    *elapsed_time = (end_time->tv_sec - start_time->tv_sec) + (end_time->tv_nsec - start_time->tv_nsec) / 1.0e9;

    // if the while loop hits the timeout, subtract the timeout time
    if (timeout == 1) {
        *elapsed_time -= 1;
        double average_per_packet_low = *elapsed_time / packets_received;
        *elapsed_time = average_per_packet_low * expected;
    }
    printf("Time between first and last packet: %.6f seconds\n", *elapsed_time);
    free(packet);

    return timeout;

}

char *calculate_compression(double *time_difference, int timeout, double elapsed_time_high_entropy, double elapsed_time_low_entropy) {

	char *compression = (char *)malloc(100 * sizeof(char));
	
	if (timeout == 1) {
		//compare
	} else {
	    //compare ∆tH - ∆tL with the threshold τ (100 ms)
	    *time_difference = elapsed_time_high_entropy - elapsed_time_low_entropy;
	}

    if (*time_difference > 0.1) {
        printf("Compression detected!\n");
        snprintf(compression, 100, "Compression detected!");
        compression[strlen(compression)] = '\0';
        return compression; //1 = compression
    } else {
        printf("No compression was detected.\n");
        snprintf(compression, 100, "No compression was detected.");
        compression[strlen(compression)] = '\0';
        return compression; //0 = no compression
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>. default for client is 7777\n", argv[0]);
        exit(EXIT_FAILURE);
    }

	//port for tcp is given from command line
    int tcp_port = atoi(argv[1]);

    int sockfd = create_and_bind(tcp_port, SOCK_STREAM, 0);

    int client_sockfd = connect_tcp(tcp_port, sockfd, 0); //0 for pre

    Config config = receive_config(client_sockfd);
    close(client_sockfd);

	int udp_sockfd = create_and_bind(config.destination_port_udp, SOCK_DGRAM, IPPROTO_UDP);

	struct pollfd timer = {
    	.fd = udp_sockfd,
    	.events = POLLIN,
    	.revents = 0
    };

    struct timespec start_time_low, end_time_low;
    struct timespec start_time_high, end_time_high;

    double elapsed_time_low_entropy, elapsed_time_high_entropy;
    
	send_packets(config, timer, &start_time_low, &end_time_low, udp_sockfd, &elapsed_time_low_entropy);

	int timeout = send_packets(config, timer, &start_time_high, &end_time_high, udp_sockfd, &elapsed_time_high_entropy);

	double time_difference;
	char *compression = calculate_compression(&time_difference, timeout, elapsed_time_high_entropy, elapsed_time_low_entropy);

	//POST PROBING
	int post_sockfd = create_and_bind(config.port_tcp_post_probing, SOCK_STREAM, 0);

	post_sockfd = connect_tcp(config.port_tcp_post_probing, post_sockfd, 1); //1 for post

    send(post_sockfd, compression, strlen(compression) + 1, 0);
    printf("Compression results sent to client\n");

    close(client_sockfd);
}

