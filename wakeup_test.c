#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cJSON/cJSON.h"

#include <memory.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define MAX_BUF_SIZE 2048

typedef enum {
	SLEEP = 0x01,
	KEEPALIVE,
	KEEPALIVE5S,
	CFGGET,
	CFGSET,
	WAKEUP,
} VISION_STATE;

unsigned char send_buf[MAX_BUF_SIZE], data_buf[MAX_BUF_SIZE];
unsigned int head, tail, data_len;

struct cmd_config {
	char *cmd;
	char *cmd_opt;
	char *value;
};

int ssl_connection(SSL *ssl, SSL_CTX* ctx)
{
	SSL_METHOD *meth;	
	X509	*server_cert;
	int sd;
	int err;
	struct sockaddr_in sa;
	char*    str;
	
	printf("%s enter ssl 0x%X, ctx 0x%x\n", __func__,ssl,ctx);
	OpenSSL_add_ssl_algorithms();
	meth = SSLv23_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);                        
	CHK_NULL(ctx);
	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */
	
	sd = socket(AF_INET, SOCK_STREAM, 0);       
	CHK_ERR(sd, "socket");
	
	memset(&sa, 0, sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = inet_addr ("52.78.86.203");   /* Server IP */
	sa.sin_port        = htons     (47878);          /* Server Port number */
	
	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));   
	CHK_ERR(err, "connect");
	
	/* ----------------------------------------------- */
	/* Now we have TCP conncetion. Start SSL negotiation. */
	
	ssl = SSL_new(ctx);      
	CHK_NULL(ssl);    
	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);    
	CHK_SSL(err);
	
	/* Following two steps are optional and not required for
	 data exchange to be successful. */
	
	/* Get the cipher - opt */
	
	printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
	
	/* Get server's certificate (note: beware of dynamic allocation) - opt */
	
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf ("Server certificate:\n");
	
	str = X509_NAME_oneline(X509_get_subject_name (server_cert),0,0);
	CHK_NULL(str);
	printf ("\t subject: %s\n", str);
	OPENSSL_free (str);
	
	str = X509_NAME_oneline(X509_get_issuer_name  (server_cert),0,0);
	CHK_NULL(str);
	printf ("\t issuer: %s\n", str);
	OPENSSL_free(str);
	
	/* We could do all sorts of certificate verification stuff here before
	 deallocating the certificate. */
	
	X509_free(server_cert);	
	printf("%s exit\n", __func__);
	return sd;
}


int calc_len(unsigned char *buf, int len)
{
	unsigned int length;
	unsigned int length1;
	printf("%s enter\n", __func__);
	memcpy(&length, buf, 4);

	length1 = htonl(length);
	printf("length 0x%X 0x%X %d\n",length, length1, length1);
	printf("%s exit\n", __func__);
	return length1;
}


int qbuf(unsigned char* buf, int len)
{	
	int ret =0;
	unsigned int length;
	printf("%s enter head %d\n", __func__,head);
	if(head+len < MAX_BUF_SIZE) {
		memcpy(&data_buf[head], buf, len);
		head += len;
	} else {
		length = MAX_BUF_SIZE - head;
		memcpy(&data_buf[head], buf, length);
		memcpy(&data_buf[0], &buf[length],len-length);
		head =len-length;
	}
	data_len += len;
	printf("%s exit head %d\n", __func__,head);
	return 0;
}

int dqbuf(unsigned char *buf, unsigned int len)
{
	int ret = 0;
	unsigned length;
	unsigned int t,t1;
	printf("%s enter tail %d\n", __func__,tail);
	t = tail;
	
	if(t+len < MAX_BUF_SIZE) {
		memcpy(buf, &data_buf[t], len);  
		t += len;
	} else {
		length = MAX_BUF_SIZE - t;
		memcpy(buf, &data_buf[t], length);
		memcpy(&buf[length], &data_buf[0], len-length);
		t = len-length;
	}
	tail = t;
	printf("%s exit tail %d\n", __func__,tail);
	return 0;
}
		

unsigned int recvfrom_server(SSL *ssl)
{
	int err=0;
	char* buf;
	unsigned int total_len = 0;
	unsigned int dat_len = 0;
	unsigned int recv_len = 0;
	unsigned char tmpbuf[1024];
	
	printf("%s enter ssl 0x%X\n", __func__,ssl);	 
	memset(tmpbuf,0,sizeof(tmpbuf));
			
	err = SSL_read(ssl, tmpbuf, 1024);
	printf("err %d\n",err);
	if(err <= 0)
		return 0;
	

	dat_len = calc_len(tmpbuf,4); 
	total_len = dat_len + 4;
	recv_len +=err;
	if(recv_len == total_len) {
		qbuf(tmpbuf, recv_len);	
	} else if(recv_len > total_len) {
		qbuf(tmpbuf, recv_len);	
		printf("ERROR!! recv_len != total_len\n");
	} else {	
		while(1) {
			memset(tmpbuf,0,sizeof(tmpbuf));
			err = SSL_read(ssl, tmpbuf, 1024);
			recv_len +=err;
			if(recv_len >= total_len) {
				break;
			}
		}
	}	
	printf("%s exit\n", __func__);
	return total_len;
}

VISION_STATE parse_packet(unsigned int len, VISION_STATE state)
{
	int ret;
	int i;
	unsigned char *buf;
	cJSON *header, *body;
	cJSON *root = cJSON_CreateObject();
	char *device_id = "ccc11111-1cc1-11d1-dd1f-c11110711111";
	char *cmd_id = "aaa223e0-10f8-11e1-b81d-0002a3d3c31c";//uuid
	char *ret_code = "0000";
	char *config = "Config";
	char *config_get = "Get";
	char *config_set = "Set";
	char *dev_id;
	char *cmd_wid;
	char *return_code;
	struct cmd_config cfg;
	char *cmd;
	char *cmd_opt;
	char *value;
	unsigned char *d;
	unsigned char b1[2048]={0};
	printf("%s enter %d\n", __func__,len);
	
	//memcpy(b1, &data_buf[4], len);
	dqbuf(&b1[0],len);
	/*for(i=0; i<len; i++){
		printf("data_buf[%d] %d,b1[%d] %d\n",i,data_buf[i],i,b1[i]);
	}
*/
	root = cJSON_Parse(&b1[4]);

	d = cJSON_Print(root);

	printf("json packet %s\n", d);
	
	header = cJSON_GetObjectItem(root, "Header");
	dev_id = cJSON_GetObjectItem(header, "deviceId");
	if(NULL == dev_id) 
		return -1;
	dev_id = cJSON_GetObjectItem(header, "deviceId")->valuestring;
			
	if(!strcmp(device_id,dev_id)) {
		body = cJSON_GetObjectItem(root, "Body");
		cmd_wid = cJSON_GetObjectItem(body, "CmdWId");
		if(NULL == cmd_wid) 
			return -1;	
		cmd_wid = cJSON_GetObjectItem(body, "CmdWId")->valuestring;
		if(!strcmp(cmd_id, cmd_wid)) {
			if(state == SLEEP) {
				return_code = cJSON_GetObjectItem(body, "ReturnCode");
				if(NULL == return_code) 
					return -1;	
				return_code = cJSON_GetObjectItem(body, "ReturnCode")->valuestring;	
				if(!strncmp(ret_code,return_code,4)) {
					state = WAKEUP;	
				} else {
					printf("invalid return code\n");
				}
			} 
		} else {
			printf("Invalid key\n");
		}
	} else {
		printf("unknown device\n");
	}
	
	cJSON_Delete(root);
	printf("%s exit\n", __func__);
	return state;
}


int make_json_packet(unsigned char *buf, char *cmd)
{
	cJSON *root;
	root = cJSON_CreateObject();
	cJSON *header, *body;
	char *device_id = "ccc11111-1cc1-11d1-dd1f-c11110711111";
	char *cmd_id = "aaa223e0-10f8-11e1-b81d-0002a3d3c31c";//uuid
	char *cmd_devinfo = "DevInfo";
	char *cmd_alive = "a";
	char *return_code = "b";
	char *format = "c";
	char *fw_version = "d";
	char *robot_sleep = "e";
	unsigned char *d;
	unsigned int len;
	unsigned int len1;
	unsigned char buf2[1024];	
	unsigned char *buf1;
	
	int i;
	printf("%s enter\n", __func__);
	memset(buf2, 0, sizeof(buf2));
	cJSON_AddItemToObject(root, "Header", header = cJSON_CreateObject());
	cJSON_AddItemToObject(root, "Body", body = cJSON_CreateObject());
	cJSON_AddItemToObject(header, "deviceId", cJSON_CreateString(device_id));
	
	if(!strncmp(cmd,"DevInfo",7)) {
		cJSON_AddItemToObject(body, "CmdWId", cJSON_CreateString(cmd_id));
		cJSON_AddItemToObject(body, "Cmd", cJSON_CreateString(cmd_devinfo));
		cJSON_AddItemToObject(body, "Format", cJSON_CreateString(format));
		cJSON_AddItemToObject(body, "Data", cJSON_CreateString(fw_version));
	} else {
		printf("unknown command\n");
	}
	d = cJSON_Print(root);
	printf("json packet %s\n", d);
	len = strlen(d);
	len1 = htonl(len);


	memset(buf2, 0, 1024);
	memcpy(buf2,&len1, sizeof(unsigned int));
	printf("buf[0]=%X %X %X %X\n", buf2[0],buf2[1],buf2[2],buf2[3]);
	
	memcpy(&buf2[4],d,len);	
	memcpy(send_buf, buf2,len+4);
	cJSON_Delete(root);
	printf("buf[0]=%X %X %X %X\n", send_buf[0],send_buf[1],send_buf[2],send_buf[3]);
	printf("%s exit\n",__func__);
	return len+4;	
}

int main(void)
{
	SSL	*ssl;
	SSL_CTX* ctx;
	int ret=0;
	int sd;
	unsigned int len=0;
	VISION_STATE state = SLEEP;
	int err;
	char *server_ip ="192.168.1.1";
	int port = 433;
	
	SSL_METHOD *meth;	
	X509	*server_cert;
	//int sd;
	//int err;
	struct sockaddr_in sa;
	char*    str;
	
	printf("%s enter ssl 0x%X, ctx 0x%x\n", __func__,ssl,ctx);

//ssl_connection();	
	OpenSSL_add_ssl_algorithms();
	meth = SSLv23_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);                        
	CHK_NULL(ctx);
	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */
	
	sd = socket(AF_INET, SOCK_STREAM, 0);       
	CHK_ERR(sd, "socket");
	
	memset(&sa, 0, sizeof(sa));
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = inet_addr (server_ip);   /* Server IP */
	sa.sin_port        = htons     (port);          /* Server Port number */
	
	err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));   
	CHK_ERR(err, "connect");
	
	/* ----------------------------------------------- */
	/* Now we have TCP conncetion. Start SSL negotiation. */
	
	ssl = SSL_new(ctx);      
	CHK_NULL(ssl);    
	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);    
	CHK_SSL(err);
	
	/* Following two steps are optional and not required for
	 data exchange to be successful. */
	
	/* Get the cipher - opt */
	
	printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
	
	/* Get server's certificate (note: beware of dynamic allocation) - opt */
	
	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
	printf ("Server certificate:\n");
	
	str = X509_NAME_oneline(X509_get_subject_name (server_cert),0,0);
	CHK_NULL(str);
	printf ("\t subject: %s\n", str);
	OPENSSL_free (str);
	
	str = X509_NAME_oneline(X509_get_issuer_name  (server_cert),0,0);
	CHK_NULL(str);
	printf ("\t issuer: %s\n", str);
	OPENSSL_free(str);
	
	/* We could do all sorts of certificate verification stuff here before
	 deallocating the certificate. */
	
	X509_free(server_cert);	
	printf("%s exit\n", __func__);
	
	
	
	
//	sd = ssl_connection(ssl,ctx);
	printf("sd %d ssl 0x%X, ctx 0x%X\n", sd, ssl, ctx);
	
	while(1) {
	//	state = get_state();
		
		if(state == SLEEP) {
			printf("state sleep\n");
			len = make_json_packet(send_buf, "DevInfo");
			err = SSL_write(ssl, send_buf, len);  
			printf("ssl_write %d\n", err);
			CHK_SSL(err);
		}
		len = recvfrom_server(ssl);
		if(len) {
			state = parse_packet(len,state);
			len = 0;
		}
	}
	
	SSL_shutdown(ssl);  /* send SSL/TLS close_notify */
		
	/* Clean up. */
	
	
	close(sd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	
	printf("ssl done\n");
	
	return 0;
}
