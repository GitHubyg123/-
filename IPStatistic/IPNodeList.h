//IP结点类,存放IP包的源IP地址和发送的包个数
class IPNode
{
private:
	long m_lIPAddress;			//IP地址
	long m_lCount;
public:
	IPNode * pNext;
	//构造函数
	IPNode(long sourceIP)
	{
		m_lIPAddress=sourceIP;
		m_lCount=1;
	}
	//数据包个数加1
	void addCount()
	{
		m_lCount++;
	}
	//返回数据包个数 
	long getCount()
	{
		return m_lCount;
	}

	//返回IP地址
	long getIPAddress()
	{
		return m_lIPAddress;
	}
};

//结点链表
class NodeList
{
	IPNode * pHead;		//链表头
	IPNode * pTail;		//链表尾
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

	//IP结点加入链表
	void addNode(long sourceIP)
	{
		if(pHead==NULL)  //链表为空
		{
			pTail=new IPNode(sourceIP);
			pHead=pTail;
			pTail->pNext=NULL;

		}
		else
		{
			for(IPNode * pTemp=pHead;pTemp;pTemp=pTemp->pNext)
			{
				//如果链表中存在此IP.发送数据包个数加1
				if(pTemp->getIPAddress()==sourceIP)
				{
					pTemp->addCount();
					break;
				}
			}
			//如果链表中没此IP.则加入链表
			if(pTemp==NULL)
			{
				pTail->pNext=new IPNode(sourceIP);
				pTail=pTail->pNext;
				pTail->pNext=NULL;
			}
		}
	}
	//输出IP结点,j即IP地址和其他发送的IP包的个数

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
