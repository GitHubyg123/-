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

//ip����ͷ���ṹ
struct ip_header{
	unsigned char ver_ihl;   //�汾��4λ+ͷ������4λ
	unsigned char tos;		//��������
	unsigned short tlen;	//�ܳ���
	unsigned short identification;	//��ʶ
	unsigned short flags_fo;	//��־+Ƭƫ��
	unsigned char ttl;		//����ʱ��
	unsigned char proto;	//Э��
	unsigned short crc;		//У���
	DWORD saddr;			//Դ��ַ
	DWORD daddr;			//Ŀ�ĵ�ַ
	unsigned int op_pad;	//ѡ��+���
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
	pcap_if_t *alldevs;				//�����豸�ṹ
	pcap_if_t *d,*head=NULL;
	pcap_t *fp;						//����������
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ
	unsigned int netmask;			//��������
	char packet_filter[] = "ip";		//����,ѡ��IPЭ��
	struct bpf_program fcode;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	//��ȡ�����豸�б�

	if(pcap_findalldevs(&alldevs,errbuf)==-1)
	{
		cout<<"Error in pcap_findalldevs:"<<errbuf;
		return;
	}
	int i=1;		//������
	if(i==0)		//���豸
	{
		cout<<"\nNO interfaces found! Make sure WinPcap is installed.\n";
		return;
	}

	if(i>=1)
	{
		int j=0;
		for(d=alldevs;d;d=d->next)	 //�г������б�,���û�����ѡ��
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

	//�Ի���ģʽ��ʽ������
	if((fp=pcap_open_live(head->name,1000,1,1000,errbuf))==NULL)
	{
		cout<<"\nUnable to open the adapter."<<endl;
		pcap_freealldevs(alldevs);
		return;

	}

	//�����������
	if(head->addresses !=NULL)
		netmask=((struct sockaddr_in *)(head->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		//û�е�ַ�����ΪC���ַ
		netmask=0xffffff;

	//���������
	if(pcap_compile(fp, &fcode,packet_filter,1,netmask)<0)
	{
		cout<<"\nUnable to compile the packet filter.check the syntax.\n";
		pcap_freealldevs(alldevs);
		return;
	}
	
	//���ù�����
	if(pcap_setfilter(fp,&fcode)<0)
	{
		cout<<"\nError setting the filter.\n";
		pcap_freealldevs(alldevs);
		return;
	}

	//��ʾ��ʾ��Ϣ��ÿ���
	cout<<"\t\tlistening on "<<head->description<<"..."<<endl<<endl;
	ofstream fout (argv[2],ios::app);		//��־��¼�ļ�
	fout<<"\tIP Statistic:("<<min<<" minutes)"<<endl;
	time_t tmp=time(NULL);
	fout<<ctime(&tmp);
	cout<<"IP Statistic:("<<min<<" minutes)"<<endl;
	fout<<"		Sour IP		"<<"\tpacket numbers"<<endl;

	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
	NodeList link;
	int res;
	time_t beg;
	time_t end;
	time(&beg);			//��ȡ��ǰʱ��
	while((res=pcap_next_ex(fp,&header,&pkt_data))>=0)
	{
		time(&end);		//���ϵͳʱ��
		if(end-beg>=min*60)	//����ͳ��ʱ��
			break;
		if(res==0)
			continue;		//��ʱ
		ip_header *ih;
		//�ҵ�IPͷ��λ��
		ih=(ip_header *)(pkt_data+14);	//14Ϊ��̫ͷ�ĳ���
		link.addNode(ih->saddr);


	}

	cout<<"Sour IP	"<<'\t'<<"packet numbers"<<endl;
	link.print(cout);
	link.print(fout);
	fout<<endl;
	
}