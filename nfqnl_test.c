#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "pcap-test.h"
#include "lib/trim.h"
#include <string.h>
#include <time.h>
#include "lib/Search.h"

#include <libnetfilter_queue/libnetfilter_queue.h>

#define HTTP_PORT 80

#define MAX_ROWS 1000000 // 최대 행 수
#define MAX_LINE_LENGTH 50 // 최대 열(한 줄의 최대 길이)

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, char forbiddenHosts[MAX_ROWS][MAX_LINE_LENGTH], int hostArrLen) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(tb, &data); // ip table
	

	if (ret >= 1){
		struct libnet_ipv4_hdr * ip_info = (struct iphdr *)data;
		if(ip_info->ip_p == IPPROTO_TCP) {
			int ip_hdr_len = (ip_info->ip_init & 0x0F) * 4;
			data += ip_hdr_len;
			struct libnet_tcp_hdr* tcp_info = (struct libnet_tcp_hdr*)(data);
			unsigned short dest_port = ntohs(tcp_info->th_dport);
			unsigned short source_port = ntohs(tcp_info->th_sport);

			if(dest_port == HTTP_PORT){
				int tcp_hdr_len = ((ntohs(tcp_info->th_flags)& 0xF000) >> 12) * 4;
				data += tcp_hdr_len;
				int http_hdr_length = ret - (ip_hdr_len + tcp_hdr_len);

				// copy data to http_res
				char http_res[http_hdr_length];
				for (int i = 0; i < http_hdr_length; i++) {
					if (i != 0 && i % 16 == 0)
						http_res[i] = "\n";
					http_res[i] = data[i];
				}

				// copy host of data to http_host
				char hostname[MAX_LINE_LENGTH];
				find_host(http_res, hostname);


				strcpy( hostname, trim( hostname )); //아래 compareStrings 구문을 사용시 반드시 이 코드 주석을 풀어야함.
				// 반대로 sql sqlit 사용시에서 반드시 이 구문을 주석처리해야함
				for(int i = 0; i < MAX_LINE_LENGTH; i++){
					strcpy(forbiddenHosts[i], trim( forbiddenHosts[i]) );
				}


				if(isGetMethod(http_res) ){

					clock_t start = clock();


					for(int i = 0; i < hostArrLen; i++){
						// int res = strcmp(hostname , forbiddenHosts[i]);
						int res = compareStrings(hostname, forbiddenHosts[i]);

						if(res == 0){
							printf("Error : Forbidden Host is %s, len : %d\n", hostname , strlen(hostname));
							printf("Error : text is %s, len : %d\n", forbiddenHosts[i], strlen(forbiddenHosts[i]));
							// printf("res = %d\n", res);
							id = -1;
							break;
							// printf("%s\n", http_res);
						}else{

						}
					}


					// my algorithm
					// printf("hostname : %s\n", hostname);
					// int res = searchStr(hostname);
					// if(res == 0){
					// 	// printf("%s  %d\n", hostname, strlen(hostname));
					// }else{
					// 	printf("Error : Forbidden Host is %s; len = %d \n", hostname, strlen(hostname));
					// 	id = -1;
					// }



					clock_t end = clock();
					double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    				printf("Execution time: %f seconds\n", time_spent);
				};
				
			}
			
		}
	}
	
    


	fputc(0, stdout);

	return id;
}

// using chatgpt.....
void find_host(char input[], char* buf){ // Warring : stack overflow attack is possible.
	// "Host: " 문자열을 찾습니다.
    char *hostStart = strstr(input, "Host: ");
	if (hostStart != NULL) {
        // "Host: " 문자열을 찾은 경우, 실제 호스트 이름의 시작 위치를 계산합니다.
        // "Host: "의 길이만큼 포인터를 이동시킵니다.
        hostStart += strlen("Host: ");
        
        // 호스트 이름의 끝을 찾습니다. (다음 줄바꿈 문자까지)
        char *hostEnd = strchr(hostStart, '\n');
        if (hostEnd != NULL) {
            // 호스트 이름을 복사하기 위한 임시 버퍼를 준비합니다.
            
            // 호스트 이름을 임시 버퍼로 복사합니다.
            strncpy(buf, hostStart, hostEnd - hostStart);
            // 문자열의 끝을 나타내는 널 문자를 추가합니다.
            buf[hostEnd - hostStart] = '\0';
        }
    }
}

const char* ONEMILLION_DOMAIN = "OneMillion-domain";



void load_file_to_array(char* filePath,char array[MAX_ROWS][MAX_LINE_LENGTH]){
	FILE *fp;
	fp = fopen(filePath, "rt");
	int c;
	

	if(fp == NULL){
		printf("file load is fail\n");
		return;
	}else{
		printf("file load is success\n");
	}

	int i = 0;

	while(fgets(array[i], MAX_LINE_LENGTH, fp) != NULL){
		array[i][strcspn(array[i], "\n")] = '\0';
		i++;
	}

	fclose(fp);	
}

/*
 if return is 0, the http request is not GET method.
 if return is 1, the http request is GET method
*/
int isGetMethod(char* str){
	char* GET = "GET";
	for(int i = 0; i < 3; i++){
		if(str[i] != GET[i])
			return 0;
	}
	return 1;
}


void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%c", buf[i]);
	}
	printf("\n");
}

char forbidHostArr[MAX_ROWS][MAX_LINE_LENGTH];

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	// char** args = (char *) data;
	// char* arg = args[1];
	u_int32_t id = print_pkt(nfa, forbidHostArr, MAX_ROWS);

	if(id == -1){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	load_file_to_array(ONEMILLION_DOMAIN, forbidHostArr); 
	// for(int i=0; i<MAX_ROWS; i++){
	// 	insertStr(forbidHostArr[i]);
	// }

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");

		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);


#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif
	printf("closing library handle  \n");
	nfq_close(h);

	exit(0);
}
