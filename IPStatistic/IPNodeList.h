//IP�����,���IP����ԴIP��ַ�ͷ��͵İ�����
class IPNode
{
private:
	long m_lIPAddress;			//IP��ַ
	long m_lCount;
public:
	IPNode * pNext;
	//���캯��
	IPNode(long sourceIP)
	{
		m_lIPAddress=sourceIP;
		m_lCount=1;
	}
	//���ݰ�������1
	void addCount()
	{
		m_lCount++;
	}
	//�������ݰ����� 
	long getCount()
	{
		return m_lCount;
	}

	//����IP��ַ
	long getIPAddress()
	{
		return m_lIPAddress;
	}
};

//�������
class NodeList
{
	IPNode * pHead;		//����ͷ
	IPNode * pTail;		//����β
public:
	NodeList()
	{
		pHead=pTail=NULL;
	}
	~NodeList()
	{
		if(pHead!=NULL)
		{
			IPNode * pTemp=pHead;
			pHead=pHead->pNext;
			delete pTemp;
		}
	}

	//IP����������
	void addNode(long sourceIP)
	{
		if(pHead==NULL)  //����Ϊ��
		{
			pTail=new IPNode(sourceIP);
			pHead=pTail;
			pTail->pNext=NULL;

		}
		else
		{
			for(IPNode * pTemp=pHead;pTemp;pTemp=pTemp->pNext)
			{
				//��������д��ڴ�IP.�������ݰ�������1
				if(pTemp->getIPAddress()==sourceIP)
				{
					pTemp->addCount();
					break;
				}
			}
			//���������û��IP.���������
			if(pTemp==NULL)
			{
				pTail->pNext=new IPNode(sourceIP);
				pTail=pTail->pNext;
				pTail->pNext=NULL;
			}
		}
	}
	//���IP���,j��IP��ַ���������͵�IP���ĸ���

	ostream & print(ostream & out)
	{
		for(IPNode* pTemp=pHead;pTemp;pTemp=pTemp->pNext)
		{
			long lTemp=pTemp->getIPAddress();
			out<<inet_ntoa(*(in_addr*)&(lTemp))<<'\t';
			out<<pTemp->getCount()<<endl;
		}
		return out;
	}
};
