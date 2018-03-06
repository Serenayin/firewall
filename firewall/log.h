#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
static pthread_mutex_t multi_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct Log{
	char datetime[32];
	char packet[15];
	int clientip;
	
	char hostname[256];
	char referer[256];
	char userAgent[256];
	
	char status_code[64];
	char server[256];
	char date[256];
	
	char error[512];
	
	void (*initLog)( struct Log *this, char *d, in_addr_t cli_addr );
	void (*writeToPath)( struct Log *this );
	
}Log;

static char logpath[256];

void initLog( struct Log *this, char *d, in_addr_t cli_addr ){
	/*time_t t;
	struct tm *p;
	t=time(NULL);
	p=localtime(&t);
	strcpy( this->datetime, asctime(p) );*/
	strcpy(this->datetime,d);
	this->clientip = cli_addr;
	strcpy(this->packet,"request from");
    bzero(this->hostname,256);
	bzero(this->referer,256);
	bzero(this->userAgent,256);
	
	bzero(this->status_code,64);
	bzero(this->server,256);
	bzero(this->date,256);
	
	bzero(this->error,512);
	if (logpath[0] == '\0') {
		strcpy(logpath, getenv("HOME"));
		strcat(logpath, "/firewall/firewall.log");
	}
}

void writeToPath( struct Log *this ){
	pthread_mutex_lock(&multi_mutex);
	FILE *fp;
	char str[16];
	if ((fp=fopen(logpath,"a"))==NULL){
		printf("log cannot be opened.\n");
		exit(1);
	}
	fprintf(fp, "%s%s clientip:%s\nhostname:%s referer:%s userAgent:%s\nstatus_code:%s server:%s date:%s\n%s\n", this->datetime, this->packet, inet_ntoa(*((struct in_addr *)&this->clientip)),
		this->hostname, this->referer,this->userAgent,
		this->status_code, this->server, this->date, this->error);
	fclose(fp);
	bzero(this->packet,15);
	strcpy(this->packet,"request from");
	//bzero(this->status_code,64);
	//bzero(this->server,256);
	//bzero(this->date,256);
	
	bzero(this->error,512);

	pthread_mutex_unlock(&multi_mutex);
}

Log *newLog(){
	Log *p = malloc(sizeof(Log));
	p->initLog = initLog;
	p->writeToPath = writeToPath;
	return p;
}

//在main里这么用：Log *log = newLog(); log->initLog(log);

typedef struct threadArg{
	int accept_sockfd;
	char date[32];
	struct in_addr clientip;
} threadArg;

typedef struct logFail{
    char datetime[32];
	char packet[15];
	int clientip;
	char error[512];	
	
	void (*init)( struct logFail *this, in_addr_t cli_addr );
	void (*writePath)( struct logFail *this );
}logFail;

void init( struct logFail *this, in_addr_t cli_addr ){
	time_t t;
	struct tm *p;
	t=time(NULL);
	p=localtime(&t);
	strcpy( this->datetime, asctime(p) );
	this->clientip = cli_addr;
	strcpy(this->packet,"request from");

	bzero(this->error,512);
	if (logpath[0] == '\0') {
		strcpy(logpath, getenv("HOME"));
		strcat(logpath, "/firewall/firewall.log");
	}
}

void writePath( struct logFail *this ){
	pthread_mutex_lock(&multi_mutex);
	FILE *fp;
	char str[16];
	if ((fp=fopen(logpath,"a"))==NULL){
		printf("log cannot be opened.\n");
		exit(1);
	}
	fprintf(fp, "%s%s clientip:%s\n%s\n", this->datetime, this->packet, inet_ntoa(*((struct in_addr *)&this->clientip)), this->error);
	fclose(fp);
	bzero(this->error,512);

	pthread_mutex_unlock(&multi_mutex);
}

logFail *newlogFail(){
	logFail *p = malloc(sizeof(logFail));
	p->init = init;
	p->writePath = writePath;
	return p;
}
