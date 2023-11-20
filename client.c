#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "cJSON/cJSON.h"
#include <fcntl.h> 
#include <sys/stat.h>
#include <errno.h>


#define BUF_SIZE 500
#define MAX_JSON_LEN 4000

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

int loadConfigFromJSON(const char *filename, Config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Could not open the configuration file");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return 0;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);

    buffer[file_size] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        perror("JSON parsing failed");
        free(buffer);
        return 0;
    }

    strcpy(config->server_ip_address, cJSON_GetObjectItem(json, "server_ip_address")->valuestring);
    config->source_port_udp = cJSON_GetObjectItem(json, "source_port_udp")->valueint;
    config->destination_port_udp = cJSON_GetObjectItem(json, "destination_port_udp")->valueint;
    config->destination_port_tcp_head_syn = cJSON_GetObjectItem(json, "destination_port_tcp_head_syn")->valueint;
    config->destination_port_tcp_tail_syn = cJSON_GetObjectItem(json, "destination_port_tcp_tail_syn")->valueint;
    config->port_tcp_pre_probing = cJSON_GetObjectItem(json, "port_tcp_pre_probing")->valueint;
    config->port_tcp_post_probing = cJSON_GetObjectItem(json, "port_tcp_post_probing")->valueint;
    config->udp_payload_size = cJSON_GetObjectItem(json, "udp_payload_size")->valueint;
    config->inter_measurement_time = cJSON_GetObjectItem(json, "inter_measurement_time")->valueint;
    config->num_udp_packets_in_train = cJSON_GetObjectItem(json, "num_udp_packets_in_train")->valueint;
    config->udp_ttl = cJSON_GetObjectItem(json, "udp_ttl")->valueint;

    free(buffer);

    return 1;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <configuration file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    Config config;
    if (!loadConfigFromJSON(argv[1], &config)) {
        fprintf(stderr, "Failed to load configuration from JSON\n");
        return EXIT_FAILURE;
    }

    //create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    //make server addr
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.port_tcp_pre_probing);
    server_addr.sin_addr.s_addr = inet_addr(config.server_ip_address);

    //tcp connect
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    //send the information from the config file
    int success = send(sockfd, (char*)&config, sizeof(config), 0);
    if (success < 0) {
        perror("Error sending configuration file information");
        exit(EXIT_FAILURE);
    }
    printf("Configuration file sent successfully\n");

    //release tcp connection
    close(sockfd);

    //create udp socket
    int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    //set dont fragment to 1, set time to a value
    int do_not_fragment = 1;
    if (setsockopt(udp_sockfd, IPPROTO_IP, IP_PMTUDISC_DO, &do_not_fragment, sizeof(do_not_fragment)) == -1) {
        perror("Don't fragment socket option");
        close(udp_sockfd);
        exit(1);
    }

    //configure udp client socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.destination_port_udp);
    inet_pton(AF_INET, config.server_ip_address, &server_addr.sin_addr);

    //set the entire packet to 0
    char *packet = (char *) calloc(config.udp_payload_size, sizeof(char));
    //check that its not null
    if (packet == NULL) {
    	perror("Error creating packet");
    	exit(EXIT_FAILURE);
    }
    //point the packet id to the first part of the packet array
    uint16_t *packetID = (uint16_t *) packet;

    //loop through train and send all packets
    sleep(3);
    int sent = 0;
    for (int i = 0; i < config.num_udp_packets_in_train; i++) {        
        //send the packet to the server
        if (sendto(udp_sockfd, packet, config.udp_payload_size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1) {
            perror("Packet sending failed");
            close(udp_sockfd);
            exit(EXIT_FAILURE);
        }
        //usleep(10);
        *packetID = htons(ntohs(*packetID) + 1);
        //printf("Packet ID number: %hu\n", ntohs(*packetID));
        sent++;
    }
    printf("Successfully sent %d low entropy packets\n", sent);

    sleep(config.inter_measurement_time);

    //open /dev/urandom for reading random data
    int urandom_fd = open("random_file", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }

	char random_data[config.udp_payload_size - sizeof(uint16_t)];
    ssize_t bytes_read = read(urandom_fd, random_data, sizeof(random_data));
    if (bytes_read == -1) {
        perror("Failed to read random data");
        close(urandom_fd);
        exit(EXIT_FAILURE);
    }
    close(urandom_fd);

    //set the entire packet to 0
    packet = (char *) calloc(config.udp_payload_size, sizeof(char));
    //check that its not null
    if (packet == NULL) {
    	perror("Error creating packet");
    	exit(EXIT_FAILURE);
    }
    
    //set packet id to zero and the rest to the random digits
    memset(packet, 0, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t), random_data, sizeof(random_data));
    
    //point the packet id to the first part of the packet array
    packetID = (uint16_t *) packet;

    sleep(3);
    sent = 0;
    //loop through second train and send all packets
    for (int i = 0; i < config.num_udp_packets_in_train; i++) {
        //send packet to the server
        if (sendto(udp_sockfd, packet, config.udp_payload_size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1) {
            perror("Packet sending failed");
            close(udp_sockfd);
            exit(EXIT_FAILURE);
        }
        *packetID = htons(ntohs(*packetID) + 1);
        sent++;
    }

    printf("Successfully sent %d high entropy packets\n", config.num_udp_packets_in_train);
 
    //start post probing process
    //change post probing port
    int post_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (post_sockfd == -1) {
        perror("Post probing socket creation failed");
        exit(EXIT_FAILURE);
    }

	//sleep in case the timeout is reached on the server
    sleep(3);

    close(udp_sockfd);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(config.server_ip_address);
    server_addr.sin_port = htons(config.port_tcp_post_probing);
    
    //tcp connect
    if (connect(post_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Post probing connection failed");
        exit(EXIT_FAILURE);
    }

    //receive compression
    char compression_buff[100];
    ssize_t bytes_received = recv(post_sockfd, compression_buff, sizeof(compression_buff) - 1, 0);
    if (bytes_received <= 0) {
        perror("Receiving results failed");
        close(post_sockfd);
        exit(EXIT_FAILURE);
    }
    compression_buff[bytes_received] = '\0';

    //print results and close socket
    printf("%s\n", compression_buff);
    close(post_sockfd);

}
