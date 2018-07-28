// IPStatistic.cpp : Defines the entry point for the console application.
//

#include <iostream.h>
#include <iomanip.h>
#include <fstream.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>

#include "pcap.h"
#include "IPNodeList.h"
#pragma comment(lib,"Wpcap.lib")
#pragma comment(lib,"Ws2_32.lib")

//ip包的头部结构
struct ip_header{
	unsigned char ver_ihl;   //版本号4位+头部长度4位
	unsigned char tos;		//服务类型
	unsigned short tlen;	//总长度
	unsigned short identification;	//标识
	unsigned short flags_fo;	//标志+片偏移
	unsigned char ttl;		//生存时间
	unsigned char proto;	//协议
	unsigned short crc;		//校验和
	DWORD saddr;			//源地址
	DWORD daddr;			//目的地址
	unsigned int op_pad;	//选项+填充
};

void main(int argc,char * argv[])
{
	if(argc!=3)
	{
		cout<<"Usage:IPStatistic time logfile"<<endl;
		cout<<"Press any key to continue..."<<endl;
		_getch();
		return;
	}
	double min=atof(argv[1]);
	pcap_if_t *alldevs;				//网络设备结构
	pcap_if_t *d,*head=NULL;
	pcap_t *fp;						//网卡描述符
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息
	unsigned int netmask;			//子网掩码
	char packet_filter[] = "ip";		//过滤,选择IP协议
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	//获取网络设备列表

	if(pcap_findalldevs(&alldevs,errbuf)==-1)
	{
		cout<<"Error in pcap_findalldevs:"<<errbuf;
		return;
	}
	int i=1;		//网卡数
	if(i==0)		//无设备
	{
		cout<<"\nNO interfaces found! Make sure WinPcap is installed.\n";
		return;
	}

	if(i>=1)
	{
		int j=0;
		for(d=alldevs;d;d=d->next)	 //列出网卡列表,让用户进行选择
		{
			cout<<++j<<": "<<d->name;
			if(d->description)
				cout<<" "<<d->description<<endl;
		}
		cout<<"\nEnter the interface number (l-"<<j<<"):";
		int k;
		cin>>k;
		if(k<1||k>j)
		{
			cout<<"out of range"<<endl;
			return;

		}
		for(d=alldevs,i=1;i<k;d=d->next,i++);
		head=d;
	}

	//以混杂模式方式打开网卡
	if((fp=pcap_open_live(head->name,1000,1,1000,errbuf))==NULL)
	{
		cout<<"\nUnable to open the adapter."<<endl;
		pcap_freealldevs(alldevs);
		return;

	}

	//获得子网掩码
	if(head->addresses !=NULL)
		netmask=((struct sockaddr_in *)(head->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		//没有地址则假设为C类地址
		netmask=0xffffff;

	//编译过滤器
	if(pcap_compile(fp, &fcode,packet_filter,1,netmask)<0)
	{
		cout<<"\nUnable to compile the packet filter.check the syntax.\n";
		pcap_freealldevs(alldevs);
		return;
	}
	
	//设置过滤器
	if(pcap_setfilter(fp,&fcode)<0)
	{
		cout<<"\nError setting the filter.\n";
		pcap_freealldevs(alldevs);
		return;
	}

	//显示提示信息及每项含义
	cout<<"\t\tlistening on "<<head->description<<"..."<<endl<<endl;
	ofstream fout (argv[2],ios::app);		//日志记录文件
	fout<<"\tIP Statistic:("<<min<<" minutes)"<<endl;
	time_t tmp=time(NULL);
	fout<<ctime(&tmp);
	cout<<"IP Statistic:("<<min<<" minutes)"<<endl;
	fout<<"		Sour IP		"<<"\tpacket numbers"<<endl;

	//释放设备列表
	pcap_freealldevs(alldevs);
	NodeList link;
	int res;
	time_t beg;
	time_t end;
	time(&beg);			//获取当前时间
	while((res=pcap_next_ex(fp,&header,&pkt_data))>=0)
	{
		time(&end);		//获得系统时间
		if(end-beg>=min*60)	//计算统计时间
			break;
		if(res==0)
			continue;		//超时
		ip_header *ih;
		//找到IP头的位置
		ih=(ip_header *)(pkt_data+14);	//14为以太头的长度
		link.addNode(ih->saddr);


	}

	cout<<"Sour IP	"<<'\t'<<"packet numbers"<<endl;
	link.print(cout);
	link.print(fout);
	fout<<endl;
	
}