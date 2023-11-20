#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include "cJSON/cJSON.h"
#include <fcntl.h> 

volatile int active_threads = 2;

struct RST_time_stamp {
    struct timespec arrival_time; // Use struct timespec for higher precision
};

//array to store arrival times of RST packets
struct RST_time_stamp rst_arrival_times[4];

//counter to keep track of captured RST packets
volatile int rst_count = 0; 

typedef struct {
    char server_ip_address[16]; //IPv4 addresses can have a maximum of 15 characters
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
} config;

typedef struct {
    config *config;
    int sockfd;
    int udp_sockfd;
} threadargs;

//handmade pseudo header struct
struct pseudo_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

//reads the json file to get the configurations into the config struct
int load_config_from_JSON(const char *filename, config *config) {
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

int create_raw_socket() {
	//create the raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation error");
        return 1;
    }

	//set HDRINCL
    int enable = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Setting IP_HDRINCL failed");
        return 1;
    }

    return sockfd;
}

int create_UDP_socket() {
	int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sockfd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    return udp_sockfd;
}

//sets all headers
void set_headers(struct iphdr *iph, struct tcphdr *tcph, config *config, int head_or_tail, struct pseudo_hdr *pseudo_header) {

	//set ip header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.128.2");
    iph->daddr = inet_addr(config->server_ip_address);

	//set tcp header
	memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source = htons(inet_addr("192.168.128.2"));
    if (head_or_tail == 1) {
    	tcph->dest = htons(config->destination_port_tcp_head_syn);
    } else {
    	tcph->dest = htons(config->destination_port_tcp_tail_syn);
    }
    tcph->seq = htonl(1);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(1);
    tcph->check = 0;
    tcph->urg_ptr = 0;

	//set pseudo header
    pseudo_header->src_addr = iph->saddr;
    pseudo_header->dst_addr = iph->daddr;
    pseudo_header->reserved = 0;
    pseudo_header->protocol = IPPROTO_TCP;
    pseudo_header->tcp_length = htons(sizeof(struct tcphdr));
}

//calculates the checksum
unsigned short calculate_checksum(const char *buf, unsigned size) {
    unsigned long sum = 0;
    //make pointer to buf as unsigned short
    const unsigned short *ptr = (const unsigned short *)buf;

	//process until the size is less than 2 bytes
    while (size > 1) {
    	//add ptr and go to next
        sum += *ptr++;
        //decrement size
        size -= sizeof(unsigned short);
    }

	//handles if the size is odd
    if (size) {
        sum += *((const unsigned char *)ptr);
    }

	//shift 16 bit and add the carry to the low 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

	//return 16 bit value
    return (unsigned short)~sum;
}

int send_SYN(struct iphdr *iph, struct tcphdr *tcph, config *config, int head_or_tail, struct pseudo_hdr *pseudo_header, int sockfd) {
	
	//set headers
    set_headers(iph, tcph, config, head_or_tail, pseudo_header);        
    
    //calculate TCP checksum including the pseudo-header
    char buffer_pseudo[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    memcpy(buffer_pseudo, (char *)pseudo_header, sizeof(struct pseudo_hdr));
    memcpy(buffer_pseudo + sizeof(struct pseudo_hdr), tcph, sizeof(struct tcphdr));
    tcph->check = 0;
    tcph->check = calculate_checksum(buffer_pseudo, sizeof(struct pseudo_hdr) + sizeof(struct tcphdr));

    //reset the IP header's total length again
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    //recreate buffer after setting the TCP checksum
    char buffer_head[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(buffer_head, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
    memcpy(buffer_head, iph, sizeof(struct iphdr));
    memcpy(buffer_head + sizeof(struct iphdr), tcph, sizeof(struct tcphdr));

    //set destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (head_or_tail == 1) {
        dest_addr.sin_port = htons(config->destination_port_tcp_head_syn);
    } else {
        dest_addr.sin_port = htons(config->destination_port_tcp_tail_syn);
    }
    dest_addr.sin_addr.s_addr = inet_addr(config->server_ip_address);

    //send the SYN packet
    if (sendto(sockfd, buffer_head, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        if (head_or_tail == 1) {
            perror("Head SYN packet send error");
        } else {
            perror("Tail SYN packet send error");
        }
    }
}

void read_random_data(config *config, char *buffer) {
    // open /dev/urandom for reading random data
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }

    ssize_t bytes_read = read(urandom_fd, buffer, config->udp_payload_size - sizeof(uint16_t));
    if (bytes_read == -1) {
        perror("Failed to read random data");
        close(urandom_fd);
        exit(EXIT_FAILURE);
    }
    close(urandom_fd);
}

int send_UDP(config *config, int low_or_high, int udp_sockfd) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->destination_port_udp);
    inet_pton(AF_INET, config->server_ip_address, &server_addr.sin_addr);

    int ttl_value = config->udp_ttl;
    if (setsockopt(udp_sockfd, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value)) < 0) {
        perror("Setting UDP socket TTL failed");
        exit(EXIT_FAILURE);
    }

	//if low entropy
	if (low_or_high == 0) {
	    //set the entire packet to 0
	    char *packet = (char *) calloc(config->udp_payload_size, sizeof(char));
	    //check that its not null
	    if (packet == NULL) {
	    	perror("Error creating packet");
	    	exit(EXIT_FAILURE);
	    }
	    memset(packet, 0, config->udp_payload_size);
	    //point the packet id to the first part of the packet array
	    uint16_t *packetID = (uint16_t *) packet;
	
	    //loop through train and send all packets
	    int sent = 0;
	    for (int i = 0; i < config->num_udp_packets_in_train; i++) {        
	        //send the packet to the server
	        if (sendto(udp_sockfd, packet, config->udp_payload_size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1) {
	            perror("Packet sending failed");
	            close(udp_sockfd);
	            exit(EXIT_FAILURE);
	        }
	        *packetID = htons(ntohs(*packetID) + 1);
	        sent++;
	    }
	    printf("Successfully sent %d low entropy packets\n", sent);
	    __sync_fetch_and_sub(&active_threads, 1);
	} else {
		//high entropy
		char random_data[config->udp_payload_size - sizeof(uint16_t)];
		read_random_data(config, random_data);
		
    	char *packet = (char *) calloc(config->udp_payload_size, sizeof(char));
	
		//set packet id to zero and the rest to the random digits
	    memset(packet, 0, sizeof(uint16_t));
	    memcpy(packet + sizeof(uint16_t), random_data, sizeof(random_data));
	    
	    //point the packet id to the first part of the packet array
	    uint16_t *packetID = (uint16_t *) packet;
	    
		int sent = 0;
	    //loop through second train and send all packets
	    for (int i = 0; i < config->num_udp_packets_in_train; i++) {
	        //send packet to the server
	        if (sendto(udp_sockfd, packet, config->udp_payload_size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1) {
	            perror("Packet sending failed");
	            close(udp_sockfd);
	            exit(EXIT_FAILURE);
	        }
	        *packetID = htons(ntohs(*packetID) + 1);
	        sent++;
	    }
	
	    printf("Successfully sent %d high entropy packets\n", config->num_udp_packets_in_train);
	}
}

void *send_packets(void *arg) {

	//set args into variables
    threadargs *args = (threadargs *)arg;
    config *config = args->config;
    int udp_sockfd = args->udp_sockfd;
    int sockfd = args->sockfd;

    struct iphdr iph_syn;
    struct tcphdr tcph_syn;
    struct pseudo_hdr pseudo_header;

	//send first head
	int head_or_tail = 1; //1 for head
	int sent = send_SYN(&iph_syn, &tcph_syn, config, head_or_tail, &pseudo_header, sockfd);
	if (sent == 1) {
		perror("Error sending SYN Head 1");
	}

	//send low entropy packets
	int low_or_high = 0; //0 for low
	sent = send_UDP(config, low_or_high, udp_sockfd);

	//send tail
    head_or_tail = 2; //2 for tail
	sent = send_SYN(&iph_syn, &tcph_syn, config, head_or_tail, &pseudo_header, sockfd);
	if (sent == 1) {
		perror("Error sending SYN Tail 1");
	}

	sleep(config->inter_measurement_time);

	//send second head
	head_or_tail = 1; //1 for head
	sent = send_SYN(&iph_syn, &tcph_syn, config, head_or_tail, &pseudo_header, sockfd);
	if (sent == 1) {
		perror("Error sending SYN Head 1");
	}
    
    //send low entropy packets
	low_or_high = 1; //1 for high
	sent = send_UDP(config, low_or_high, udp_sockfd);

	//send tail
    head_or_tail = 2; //2 for tail
	sent = send_SYN(&iph_syn, &tcph_syn, config, head_or_tail, &pseudo_header, sockfd);
	if (sent == 1) {
		perror("Error sending SYN Tail 1");
	}
	//decrement number of active threads
	__sync_fetch_and_sub(&active_threads, 1);	
}

void *receive_packets(void *arg) {

    time_t start_time, current_time;
    time(&start_time);
    const int timeout_seconds = 60;

	//set args into variables
    threadargs *args = (threadargs *)arg;
    int sockfd = args->sockfd;

    //listen for RST packets
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buffer[4096]; 

    while (rst_count < 4) {
        time_t received_time;
        time(&received_time);
        time(&current_time); // Update current time inside the loop
        if (difftime(current_time, start_time) >= timeout_seconds) {
            //Timeout reached
            printf("Receive timeout reached\n");
            return NULL;
        }
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_addr, &addr_len);
        if (recv_len < 0) {
            perror("Receive RST error");
            return NULL;
        } else {
            //check if packet is RST
            struct tcphdr *received_tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
            if (received_tcph->rst) {
                //RST received, store the time
                clock_gettime(CLOCK_MONOTONIC, &(rst_arrival_times[rst_count].arrival_time));
	            printf("Received a TCP RST packet\n");
	            rst_count++;
            } else {
                //not rst
                printf("Received a packet that is not a TCP RST\n");
            }
        }
    }
    __sync_fetch_and_sub(&active_threads, 1);
}

int create_threads(config *config, int sockfd, int udp_sockfd) {
    //one thread for sending
    pthread_t senderThread;
    threadargs sender_args = { config, sockfd, udp_sockfd };
    if (pthread_create(&senderThread, NULL, send_packets, (void *)&sender_args) != 0) {
        perror("Error creating thread");
        return EXIT_FAILURE;
    }
    
    //one thread for receiving && maybe timeout?
	pthread_t receiverThread;
	threadargs receiver_args = { config, sockfd, udp_sockfd };
	if (pthread_create(&receiverThread, NULL, receive_packets, (void *)&receiver_args) != 0) {
        perror("Error creating thread");
        return EXIT_FAILURE;
    }
    
    //wait for threads to finish
	while (active_threads > 0) {
	    usleep(10000);
	}
	
	pthread_join(senderThread, NULL);
	pthread_join(receiverThread, NULL);
	return 0;    	
}

void calculate_compression() {
	//error handling
	if (rst_count < 4) {
        printf("Insufficient number of timestamps to calculate differences\n");
    }

    //calculate differences between timestamps
    struct timespec diff1, diff2;

    // Difference between the first and second timestamp
    diff1.tv_sec = rst_arrival_times[1].arrival_time.tv_sec - rst_arrival_times[0].arrival_time.tv_sec;
    diff1.tv_nsec = rst_arrival_times[1].arrival_time.tv_nsec - rst_arrival_times[0].arrival_time.tv_nsec;

	// Difference between the third and fourth timestamp
	diff2.tv_sec = rst_arrival_times[3].arrival_time.tv_sec - rst_arrival_times[2].arrival_time.tv_sec;
	diff2.tv_nsec = rst_arrival_times[3].arrival_time.tv_nsec - rst_arrival_times[2].arrival_time.tv_nsec;

	printf("Difference between first and second timestamp: %ld nanoseconds\n", diff1.tv_nsec);
	printf("Difference between third and fourth timestamp: %ld nanoseconds\n", diff2.tv_nsec);

	long diff_threshold = 100 * 1000000; // 100 milliseconds in nanoseconds

    // Calculate the absolute difference between the first and last packets of the two trains
    long absolute_diff = labs(diff1.tv_nsec - diff2.tv_nsec);

    if (absolute_diff > diff_threshold) {
        printf("Compression detected!\n");
    } else {
        printf("No compression was detected.\n");
    }
}

int main(int argc, char *argv[]) {

    //takes in config file
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <configuration file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    //creates config struct
    config config;
    if (!load_config_from_JSON(argv[1], &config)) {
        fprintf(stderr, "Failed to load configuration from JSON\n");
        return EXIT_FAILURE;
    }

    int sockfd = create_raw_socket();
	int udp_sockfd = create_UDP_socket();

	create_threads(&config, sockfd, udp_sockfd);

	close(sockfd);
	close(udp_sockfd);

	calculate_compression();
	return 0;
}
