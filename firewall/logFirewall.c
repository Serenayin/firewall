#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include "log.h"
#define REMOTE_SERVER_PORT 80
#define BUF_SIZE 4096
#define QUEUE_SIZE 100
#define BLOCKED_SERVER "bbs.sjtu.edu.cn"
char ALLOWED_CLIENTIP[20] = "127.0.0.1";
char lastservername[256] = " ";
int lastserverip = 0;
pthread_mutex_t conp_mutex;// = PTHREAD_MUTEX_INITIALIZER;

int checkclient(in_addr_t cli_addr, char **p){
	int allowedip;
	inet_aton(ALLOWED_CLIENTIP,(struct in_addr *)&allowedip);
	if(allowedip != cli_addr){
		char str[40] =  "Client IP authentication failed!\n";
		strcpy(*p,"Client IP authentication failed!\n");
		//*p += strlen("Client IP authentication failed!\n");
		printf("%s",str);//error
		return -1;
	}
	return 1;
}

int mygethostname(char * buf,char * hostname,int length){
	char *p;
	int i,j = 0;
	bzero(hostname,256);
	p=strstr(buf,"Host:");
	if(!p)
		p=strstr(buf,"host:");
	if (!p) {
	    return -1;
	}
	i = (p-buf) + 6;
	for(j = 0;i < length;i++,j++){
		if(buf[i]=='\r'){
			hostname[j] = '\0';
			return 0;
		}
		else
			hostname[j] = buf[i];
	}
	return -1;
}

int getReferer(char* buf,char *referer,int length){
	char *p;
	int i,j = 0;
	bzero(referer,256);
	p=strstr(buf,"Referer:");
	if(!p)
		p=strstr(buf,"referer:");
	if (!p) {
	    strcpy(referer, "(null)");
	    return 0;
	}
	i = (p-buf) + 9;
	for(j = 0;i<length;i++,j++){
		if(buf[i] == '\r'){
			referer[j] = '\0';
			return 0;
		}
		else
			referer[j] = buf[i];
	}
	return -1;
}

int getUserAgent(char* buf,char *useragent,int length){
	char *p;
	int i,j = 0;
	bzero(useragent,256);
	p=strstr(buf,"User-Agent:");
	if(!p)
		p=strstr(buf,"user-Agent:");
	if (!p) {
	    strcpy(useragent, "(null)");
	    return 0;
	}
	i = (p-buf) + 12;
	for(j = 0;i<length;i++,j++){
		if(buf[i] == '\r'){
			useragent[j] = '\0';
			return 0;
		}
		else
			useragent[j] = buf[i];
	}
	return -1;
}

int getStatus(char* buf,char *status,int length){
	char *p;
	int i,j = 0;
	bzero(status,64);
	p=strstr(buf," ");
	if(!p)
		p=strstr(buf," ");
	if(!p) return -1;
	i = (p-buf) + 1;
	for(j = 0;i<length;i++,j++){
		if(buf[i] == ' '){
			status[j] = '\0';
			return 0;
		}
		else
			status[j] = buf[i];
	}
	return -1;
}

int getDate(char* buf,char *date,int length){
	char *p;
	int i,j = 0;
	bzero(date,256);
	p=strstr(buf,"Date:");
	if(!p)
		p=strstr(buf,"date:");
	if (!p) {
	    strcpy(date, "(null)");
	    return 0;
	}
	i = (p-buf) + 6;
	for(j = 0;i<length;i++,j++){
		if(buf[i] == '\r'){
			date[j] = '\0';
			return 0;
		}
		else
			date[j] = buf[i];
	}
	return -1;
}

int getServer(char* buf,char *server,int length){
	char *p;
	int i,j = 0;
	bzero(server,256);
	p=strstr(buf,"Server:");
	if(!p)
		p=strstr(buf,"server:");
	if (!p) {
	    strcpy(server, "(null)");
	    return 0;
	}
	i = (p-buf) + 8;
	for(j = 0;i<length;i++,j++){
		if(buf[i] == '\r'){
			server[j] = '\0';
			return 0;
		}
		else
			server[j] = buf[i];
	}
	return -1;
}

int checkserver(char * hostname, char **p){
	if(strstr(hostname,BLOCKED_SERVER)!= NULL){
		strcpy(*p,"Destination blocked!\n");
		//*p += strlen("Destination blocked!\n");
		printf("Destination blocked!\n");//error
		return -1;
	}
	return 0;
}

int connectserver(char * hostname, char **p){
	int cnt_stat;
	struct hostent * hostinfo;
	struct sockaddr_in server_addr;
	int remotesocket;
	remotesocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(remotesocket<0){
		strcpy(*p,"can not create socket!\n");
		//*p += strlen("can not create socket!\n");
		printf("can not create socket!\n");
		return -1;
	}
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(REMOTE_SERVER_PORT);
	pthread_mutex_lock(&conp_mutex);
	if(strcmp(lastservername,hostname)!=0){
		hostinfo=gethostbyname(hostname);
		if(!hostinfo){
			strcpy(*p,"gethostbyname failed\n");
			//*p += strlen("gethostbyname failed\n");
			printf("gethostbyname failed\n");
			return -1;
		}
		strcpy(lastservername,hostname);
		lastserverip=*(int *)hostinfo->h_addr;
		server_addr.sin_addr.s_addr = lastserverip;
	}
	else
		server_addr.sin_addr.s_addr = lastserverip;
	pthread_mutex_unlock(&conp_mutex);
	cnt_stat=connect(remotesocket,(struct sockaddr *)&server_addr,sizeof(server_addr));
	if(cnt_stat<0){
		strcpy(*p,"remote connnect failed!\n");
		//*p += strlen("remote connnect failed!\n");
		printf("remote connnect failed! err = %d\n", cnt_stat);
		close(remotesocket);
		return -1;
	}
	else 
		printf("connected remote server--------------->%s:%u.\n",inet_ntoa(server_addr.sin_addr),ntohs(server_addr.sin_port));
	return remotesocket;
}

void dealonereq(void *arg){
	threadArg *childarg = (threadArg *)arg;
	char buf[BUF_SIZE];
	int bytes;
	char recvbuf[BUF_SIZE];
	Log *log = newLog();
	log->initLog(log, childarg->date, childarg->clientip.s_addr);
	char *ptr = log->error;
	//char hostname[256];  log->hostname
	int remotesocket;
	int accept_sockfd = childarg->accept_sockfd;
	pthread_detach(pthread_self());
	bzero(recvbuf,BUF_SIZE);
	bzero(buf,BUF_SIZE);
	bytes=read(accept_sockfd,buf,BUF_SIZE);
	if(bytes<=0){
        log->writeToPath(log);
		close(accept_sockfd);
	    free(log);
	    free(childarg);
		return;
	}
	mygethostname(buf,log->hostname,bytes);
	getReferer(buf, log->referer, bytes);
	getUserAgent(buf, log->userAgent, bytes);
	if(strlen(log->hostname)==0){
		strcpy(ptr,"Invalid host name\n");
		//childarg->ptr += strlen("Invalid host name\n");
		printf("Invalid host name");
        log->writeToPath(log);
		close(accept_sockfd);
	    free(log);
	    free(childarg);
		return;
	}
	if(checkserver(log->hostname, &(ptr))==-1){
        log->writeToPath(log);
		close(accept_sockfd);
	    free(log);
	    free(childarg);
		return;
	}
	remotesocket=connectserver(log->hostname, &(ptr));
	if(remotesocket == -1){
        log->writeToPath(log);
		close(accept_sockfd);
	    free(log);
	    free(childarg);
		return;
	}
	send(remotesocket,buf,bytes,0);
	log->writeToPath(log);
	int flag = 0;
	while(1){
		int readSizeOnce = 0;
		readSizeOnce = read(remotesocket,recvbuf,BUF_SIZE);
		if(readSizeOnce <= 0)
			break;
		if (!flag){
			getStatus(recvbuf,log->status_code,readSizeOnce);
			getDate(recvbuf,log->date,readSizeOnce);
			getServer(recvbuf,log->server,readSizeOnce);
			flag = 1;
		}
		
		strcpy(log->packet,"respond to");
		send(accept_sockfd,recvbuf,readSizeOnce,0);
		log->writeToPath(log);
	}
	close(remotesocket);
	close(accept_sockfd);
	free(log);
	free(childarg);
}

int main(int argc,char ** argv){
	short port = 0;
	char opt;
	struct sockaddr_in cl_addr,proxyserver_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int sockfd,accept_sockfd,on=1;
	pthread_t Clitid;
	while((opt = getopt(argc,argv,"p:")) != EOF){
		switch(opt){
			case 'p':
				port = (short)atoi(optarg);
				break;
			default:
				printf("Usage:%s -p port\n",argv[0]);
				return -1;
		}
	}
	if(port==0){
		printf("Invalid port number, try again.\n");
		printf("Usage: %s -p port\n",argv[0]);
		return -1;
	}
	sockfd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(sockfd<0){
		printf("Socket failed...Abort...\n");
		return -1;
	}
	memset(&proxyserver_addr,0,sizeof(proxyserver_addr));
	proxyserver_addr.sin_family=AF_INET;
	proxyserver_addr.sin_port = htons(port);
	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(char*)&on,sizeof(on));
	if(bind(sockfd,(struct sockaddr *)&proxyserver_addr,sizeof(proxyserver_addr))<0)
	{
		printf("Bind failed...Abort...\n");
		return -1;
	}
	if(listen(sockfd,QUEUE_SIZE)<0){
	printf("Listen failed...Abort...\n");
	return -1;
	}
	while(1){
		accept_sockfd = accept(sockfd,(struct sockaddr *)&cl_addr,&sin_size);
	    logFail *fail = newlogFail();
	    fail->init(fail, cl_addr.sin_addr.s_addr);
	    char *ptr = fail->error;
		if(accept_sockfd<0){
			printf("accept failed");
			continue;
		}
		printf("Received a request from %s:%u\n",inet_ntoa(cl_addr.sin_addr),ntohs(cl_addr.sin_port));

		if(checkclient(cl_addr.sin_addr.s_addr, &ptr)==1){
		    threadArg *childarg = malloc(sizeof(threadArg));
			childarg->accept_sockfd = accept_sockfd;
			strcpy(childarg->date,fail->datetime);
			childarg->clientip = cl_addr.sin_addr;
			pthread_create(&Clitid,NULL,(void *)dealonereq,childarg);
		}
		else{
            fail->writePath(fail);
			close(accept_sockfd);
        }
        free(fail);
	}
	return 0;
}
