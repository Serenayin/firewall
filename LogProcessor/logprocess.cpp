#include "logprocess.h"
#include "ui_logprocess.h"
#include <QFile>
#include <QTextStream>
#include <QProcessEnvironment>
#include <QMessageBox>
#include <QTextCursor>
#include <stdio.h>  //标准输入输出（如printf等）相关的头文件
#include <iostream>
#include <stdlib.h>
#include <string>   //字符串操作相关的头文件
#include <string.h>
#include <fstream>  //文件操作相关的头文件

logProcess::logProcess(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::logProcess)
{
    ui->setupUi(this);
}

logProcess::~logProcess()
{
    delete ui;
}

void logProcess::on_findButton_clicked()
{
    QString searchString = ui->lineEdit->text();
    if ( !ui->textEdit->find(searchString ) )//QTextDocument::FindBackward
    {
        QMessageBox::warning(this, tr("Attention"), tr("Reach the end with no more %1").arg(searchString),QMessageBox::Ok);
        ui->textEdit->moveCursor(QTextCursor::Start);
    }
}

void logProcess::on_openButton_clicked()
{
    loadTextFile();
}

void logProcess::on_checkButton_clicked()
{
    std::string recordStr[6];
    recordStr[0]="remote connect failed!";
    recordStr[1]="can not create socket!";
    recordStr[2]="gethostbyname failed";
    recordStr[3]="Invalid host name";
    recordStr[4]="Destination blocked!";
    recordStr[5]="Client IP authentication failed!";  //用于记录敏感字段
    int recordTime[6]= {0,0,0,0,0,0};  //可疑记录出现的次数

    std::ifstream in;
    FILE *fw; //日志文件不能写回，再建一个输出文件存放分析结果；
    std::string temp; //用于读取日志中每行的记录
    char logpath[32];     //日志文件名（路径）
    std::string env=getenv("HOME");
    env += "/firewall/firewall.log";
    strcpy(logpath,env.c_str());
    in.open(logpath);
    if (!in){
        QMessageBox::warning(this, tr("Warning"), tr("log cannot be opened."),QMessageBox::Ok);
        exit(1);
    }//打开日志文件
    char checkpath[32];
    std::string check=getenv("HOME");
    check += "/firewall/check.log";
    strcpy(checkpath,check.c_str());
    if((fw=fopen(checkpath,"w"))==NULL){
        QMessageBox::warning(this, tr("Warning"), tr("check.log cannot be opened."),QMessageBox::Ok);
        exit(1);
    }  //另打开一个文件存放审计分析结果

    std::string recordIp[256]; //存储远程服务器IP地址
    int ipNum=0;           //IP地址的个数
    size_t p;
    // 自动统计分析日志文件模式
    while(getline(in,temp))//逐行读取整个文件
    {
        for(int k=0;k<6;k++){
            if(temp==recordStr[k])
                ++recordTime[k];//分别统计敏感字段出现的次数
        }

        // 审计远程服务器IP模式
        char ip[256];
        char key[]="hostname:";
        p=temp.find(key);
        if(p==std::string::npos)
            continue;
        int i = p + 9;
        for(int j = 0;i<256;i++,j++){
            if(temp[i] == ' '){
                ip[j] = '\0';
            }
            else
                ip[j] = temp[i];
        }
        std::string str(ip);
        if(strlen(ip)==0)
            continue;
        int count=0;
        if(ipNum==0){
            recordIp[ipNum]=str;
            ipNum++;
        }
        else{
            for(int i=0;i<ipNum;i++)
                if(recordIp[i]!=ip){
                    ++count;
                }
            if(count == ipNum){
                recordIp[ipNum]=str;          //将获取到IP地址存入数组
                ipNum++;
            }
        }
    }

    // 根据敏感字段出现的次数来对用户进行提醒
    for(int k=0;k<6;k++){
        char Str[32];
        strcpy(Str, recordStr[k].c_str());
        fprintf(fw, "日志中出现%32s：%6d次\n", Str, recordTime[k]);
        //cout<<"日志中出现: "<<std::right<<setw(6)<<recordTime[k]<<" 次 "<<recordStr[k]<<endl;
    }
    if(recordTime[4]>10){
        fprintf(fw, "警告：过多的非法连接，请检查:“Destination blocked”\n");
        QMessageBox::warning(this, tr("Warning"), tr("警告：过多的非法连接，请检查:“Destination blocked”"),QMessageBox::Ok);
    }
    if(recordTime[5]>0){
        fprintf(fw, "警告：有非法用户连接，请检查:“Client IP authentication failed”\n");
        QMessageBox::warning(this, tr("Warning"), tr("警告：有非法用户连接，请检查:“Client IP authentication failed”"),QMessageBox::Ok);
    }

    if(ipNum>0)
    {
        fprintf(fw, "共有 %d 条远程服务器域名记录\n", ipNum );
        fprintf(fw, "客户端IP地址为：127.0.0.1\n");
        fprintf(fw, "连接远程服务器域名:\n");
        for(int i=0;i<ipNum;i++){
            char Str[32];
            strcpy(Str, recordIp[i].c_str());
            fprintf(fw, "    %s\n", Str);//cout<<recordIp[i]<<endl;
        }
        QMessageBox::information(this, tr("Attention"), tr("客户端(IP地址为：127.0.0.1)共有 %1 条远程服务器域名记录,具体请查看check.log").arg(ipNum),QMessageBox::Ok);
    }
    else
        fprintf(fw, "防火墙日志中无远程服务器域名记录");//cout<<"防火墙日志中无IP地址记录"<<endl;

    in.close();
    fclose(fw);
}

void logProcess::loadTextFile()
{
    QProcessEnvironment envirenment = QProcessEnvironment::systemEnvironment();
    QString qtDir = envirenment.value("HOME");
    QFile inputFile(qtDir + "/firewall/firewall.log");
    inputFile.open(QIODevice::ReadOnly);

    QTextStream in(&inputFile);
    QString line = in.readAll();
    inputFile.close();

    ui->textEdit->setPlainText(line);
    QTextCursor cursor = ui->textEdit->textCursor();
    cursor.movePosition(QTextCursor::Start, QTextCursor::MoveAnchor, 1);
}
