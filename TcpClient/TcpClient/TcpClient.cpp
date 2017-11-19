// TcpClient.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "winerror.h"
#include "Winsock2.h"
#pragma comment(lib, "ws2_32")
#include "windows.h"
#include <iostream>
#include <ws2tcpip.h>
#include <stdio.h>

HANDLE hIocp;
int mBuffersize;
/// 宏定义
#define 发送数据 1
#define 数据到达 2
#define 连接断开 3
#define 发生错误 4


typedef struct OverlappedP{
	WSAOVERLAPPED overlapped;
	SOCKET socket;
	int OperationType;
	int Callback;
	WSABUF wsabuf;
	char* buf;
	DWORD sendbuflen;/*已发送长度*/
	sockaddr_in addr;
	int Extra;
	u_short wPort;
	char* errInfo;
}OVERLAPPEDP;


typedef int(*Callback)(int, int, int, OverlappedP*);
//操作类型  数据地址 数据长度 结构指针

BOOL InitWinsock(int buffersize);
DWORD WINAPI Worker(HANDLE iocp);
void funRecv(OverlappedP* over, DWORD Transferred);
void funSend(OverlappedP* overlapped, DWORD Transferred);
void Byte2Hex(const char *sSrc, char *sDest, int nSrcLen);
OverlappedP* Connect(char* serverIp, u_short serverPort, int callback, int Extra);
SOCKET GetSocket(OverlappedP* ptr);
u_short GetClientPort(OverlappedP* ptr);
u_short GetServerPort(OverlappedP* ptr);
int GetServerAddr(OverlappedP* ptr);
int GetClientExtra(OverlappedP* ptr);
int Send(OverlappedP* recv, char* buf, int len);
int Close(OverlappedP* recv);
char* GetErrInfo(OverlappedP* ptr);
void Destory();

int _tmain(int argc, _TCHAR* argv[])
{

	if (!InitWinsock(8192)){
		printf("init error.\n");
		return -1;
	}
	printf("init suc\n");
	OverlappedP* ptr = Connect("123.206.208.208", 8081, 0, 100);
	if (ptr == NULL){
		printf("connet error.\n");
		return -1;
	}
	printf("Connect suc\n");
	Sleep(2000);
	Close(ptr);
	while (1);

	return 0;
}


/*
* 初始化socket环境
*/
BOOL InitWinsock(int buffersize){

	SYSTEM_INFO system;

	DWORD ThreadID;
	//创建IOCP
	if ((hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0)) == NULL){
		printf("CreateIoCompletionPort failed!\n");
		return false;
	}
	//获取系统信息
	GetSystemInfo(&system);
	//计算最佳线程数量
	int ThreadCount = system.dwNumberOfProcessors * 2 + 2;
	for (int i = 0; i < ThreadCount; i++){
		HANDLE ThreadHandle;
		//创建IOCP线程 运行Worker
		if ((ThreadHandle = CreateThread(NULL, 0, Worker, hIocp, 0, &ThreadID)) == NULL){
			printf("CreateThread failed with error: %d\n", GetLastError());
			return false;
		}
		//关闭线程句柄
		CloseHandle(ThreadHandle);
	}
	WSAData wsd;
	//初始化winsock环境
	int iResult = WSAStartup(0x0202, &wsd);
	if (iResult != 0){
		printf("WSAStartup failed with error: %d\n", iResult);
		return false;
	}
	mBuffersize = buffersize;
	return true;

}

/*
* 工作线程
*/
DWORD WINAPI Worker(HANDLE iocp){
	DWORD Transferred;
	SOCKET lpCompletekey;//PULONG_PTR
	OverlappedP* lpOverlapped;//LPOVERLAPPED
	int ret = 0;
	while (true){
		if (GetQueuedCompletionStatus(iocp, &Transferred, (PULONG_PTR)&lpCompletekey, (LPOVERLAPPED *)&lpOverlapped, 500)){
			printf("get ptr: %p, Transferred=%d\n", lpOverlapped, Transferred);
			//OverlappedP
			switch (lpOverlapped->OperationType){
			case 数据到达:
				funRecv(lpOverlapped, Transferred);
				break;
			case 发送数据:
				funSend(lpOverlapped, Transferred);
				break;
			default:
				break;
			}
		}
		else{
			int dwCode = WSAGetLastError();
			if (dwCode != 258){//TIME_OUT
				printf("WSAGetLastError ret code: %d\n", dwCode);
				Callback funCall = (Callback)lpOverlapped->Callback;
				switch (dwCode){
				case ERROR_NETNAME_DELETED:
					//非正常断开: 服务端/客户端 未调用shutdown就直接调用closesocket(未完成四次挥手).
					lpOverlapped->errInfo = "TCP connection abnormal disconnect, not completed the four wave.";//TCP连接异常断开, 未完成四次挥手。
					if (lpOverlapped->Callback != 0){
						funCall(连接断开, 0, 0, lpOverlapped);
						free(lpOverlapped);
					}
					printf("非正常断开: 服务端/客户端 未调用shutdown就直接调用closesocket(未完成四次挥手).\n");
					break;
				case WSA_OPERATION_ABORTED://客户端正常断开：调用shutdownhour调用closesocket就会重现这个代码
					lpOverlapped->errInfo = "The TCP client actively closes the connection and has completed the four wave.";//TCP连接异常断开, 未完成四次挥手。
					//TCP客户端主动关闭连接，并且已经完成四次挥手。
					printf("正常断开: TCP客户端主动关闭连接，并且已经完成四次挥手.\n");
					if (lpOverlapped->Callback != 0){
						funCall(连接断开, 0, 0, lpOverlapped);
						free(lpOverlapped);
					}
					
					//因为套接字的关闭，一个重叠操作被取消，或者是执行了WSAIoctl()函数的SIO_FLUSH命令，错误值依赖于操作系统
					//printf("ret false code: %d\n", c);
					break;
				default:
					break;


					
						
				}
			}

		}
	}
	return 0;
}

/*
* 数据到达
*/
void funRecv(OverlappedP* over, DWORD Transferred){
	unsigned long iFlag = 0;
	int ret = 0;
	Callback funCall = (Callback)over->Callback;

	if (Transferred == 0){
		//1.GetQueuedCompletionStatus返回值为TRUE，则表示客户端是主动断开，TCP / IP协议中断开时的4次握手完成了。
		//2.GetQueuedCompletionStatus返回值为FALSE，则表示客户端是意外断开，4次握手只完成了一部分。SOCKET错误号为：64
		//所以lpNumberOfBytes = 0, 服务端都要处理客户断开的操作。

		//TCP连接正常断开, 已完成四次挥手。
		over->errInfo = "The TCP connection was broken normally, and the four wave was completed.";
		if (over->Callback != 0){
			funCall(连接断开, 0, 0, over);
			over->errInfo = 0;
		}
		free(over);
		printf("TCP连接正常断开, 已完成四次挥手。\n");
		return;
	}

	if (over->Callback != 0){
		funCall(数据到达, (int)over->wsabuf.buf, Transferred, over);
	}

	
	char* hex = (char *)malloc(Transferred * 2 * sizeof(char) + 1);
	Byte2Hex(over->wsabuf.buf, hex, Transferred);
	hex[Transferred * 2] = 0;
	printf("recv=[%s]\n", hex);
	free(hex);
	

	ret = WSARecv(over->socket, &over->wsabuf, 1, &over->sendbuflen, &iFlag, &over->overlapped, 0);
	if (ret == SOCKET_ERROR){
		ret = WSAGetLastError();
		//#define ERROR_INVALID_HANDLE 6L //The handle is invalid.
		if (ret != WSA_IO_PENDING){
			over->errInfo = "WSARecv failed.";
			if (over->Callback != 0){
				char err[256];
				sprintf(err, "WSARecv failed with Code: %d.", ret);
				over->errInfo = err;
				funCall(发生错误, 0, 0, over);
				over->errInfo = 0;
				printf("%s\n", err);
				free(over);
			}
			printf("WSARecv failed!");

		}
	}

}

/*
* 发送成功
*/
void funSend(OverlappedP* overlapped, DWORD Transferred){
	overlapped->sendbuflen += Transferred;
	if (overlapped->sendbuflen < overlapped->wsabuf.len){
		overlapped->wsabuf.len -= overlapped->sendbuflen;
		overlapped->wsabuf.buf += overlapped->sendbuflen;
		int iFlag = 0;
		WSASend(overlapped->socket, &overlapped->wsabuf, 1, NULL, iFlag, (LPWSAOVERLAPPED)&overlapped, 0);
	}
	else{
		if (overlapped->Callback != 0){
			Callback funCall = (Callback)overlapped->Callback;
			funCall(overlapped->OperationType, (int)overlapped->wsabuf.buf, overlapped->wsabuf.len, overlapped);
		}
		free(overlapped->buf);
		free(overlapped);
	}
	printf("send suc\n");
}

/*
* 字节数组转十六进制文本
*/
void Byte2Hex(const char *sSrc, char *sDest, int nSrcLen)
{
	int  i;
	char szTmp[3];

	for (i = 0; i < nSrcLen; i++)
	{
		sprintf(szTmp, "%02X", (unsigned char)sSrc[i]);
		memcpy(&sDest[i * 2], szTmp, 2);
	}
	return;
}


/*
* 链接服务器 返回一个结构指针
*/
OverlappedP* Connect(char* serverIp, u_short serverPort, int callback, int Extra){
	struct sockaddr_in saDest;
	memset(&saDest, 0, sizeof(saDest));

	saDest.sin_addr.S_un.S_addr = inet_addr(serverIp);
	saDest.sin_port = htons(serverPort);
	saDest.sin_family = AF_INET;

	SOCKET sid = INVALID_SOCKET;
	//创建socket句柄
	sid = socket(AF_INET, SOCK_STREAM, 0);
	if (sid == INVALID_SOCKET){
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}
	sockaddr ad;
	
	//链接服务器
	int ret = connect(sid, (sockaddr*)&saDest, sizeof(sockaddr));
	if (ret == SOCKET_ERROR){
		printf("connnet failed %d\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}

	//socket和iocp绑定
	CreateIoCompletionPort((HANDLE)sid, hIocp, sid, 0);

	OverlappedP* ptr = (OverlappedP *)malloc(sizeof(OverlappedP));
	ptr->wsabuf.len = mBuffersize;
	ptr->wsabuf.buf = (char *)malloc(mBuffersize * sizeof(char));
	ptr->OperationType = 数据到达;
	ptr->socket = sid;
	ptr->Callback = callback;
	ptr->Extra = Extra;
	struct sockaddr addr;
	int memlen = sizeof(sockaddr);
	//获取客户端口
	getsockname(sid, &addr, &memlen);
	sockaddr_in* addrin = (sockaddr_in *)&addr;
	ptr->wPort = addrin->sin_port;
	DWORD iFlag = 0;
	int len = sizeof(sockaddr);
	//初始结构 以防提示Event句柄无效
	memset(&ptr->overlapped, 0, sizeof(OVERLAPPED));
	//UDP -> ret = WSARecvFrom(sid, &ptr->wsabuf, 1, &ptr->sendbuflen, &iFlag, (sockaddr *)&ptr->addr, &len, &ptr->overlapped, 0);

	//发送WSARecv等待接收数据
	ret = WSARecv(sid, &ptr->wsabuf, 1, &ptr->sendbuflen, &iFlag, &ptr->overlapped, 0);
	if (ret == SOCKET_ERROR){
		ret = WSAGetLastError();
		//#define ERROR_INVALID_HANDLE 6L //The handle is invalid.
		if (ret != WSA_IO_PENDING){
			return NULL;
		}
	}
	return ptr;
}

/*
* 获取本地SOCKET句柄
*/
SOCKET GetSocket(OverlappedP* ptr){
	return ptr->socket;
}

/*
* 获取客户端口
*/
u_short GetClientPort(OverlappedP* ptr){
	return ptr->wPort;
}

/*
* 获取远程端口
*/
u_short GetServerPort(OverlappedP* ptr){
	return ptr->addr.sin_port;
}

/*
* 获取远程IP地址
*/
int GetServerAddr(OverlappedP* ptr){
	return ptr->addr.sin_addr.S_un.S_addr;
}

/*
* 获取附加数据
*/

int GetClientExtra(OverlappedP* ptr){
	return ptr->Extra;
}

/*
* 获取错误信息
*/
char* GetErrInfo(OverlappedP* ptr){
	return ptr->errInfo;
}

/*
* 发送数据
* 返回值： -1（SOCKET无效） -2 发送失败 可用WSAGetLastError()获取错误代码
*/
int Send(OverlappedP* recv, char* buf, int len){
	if (recv->socket == INVALID_SOCKET || recv->socket == SOCKET_ERROR){
		return -1;
	}
	

	OverlappedP* ptr = (OverlappedP*)malloc(sizeof(OverlappedP));
	printf("send ptr: %p\n", ptr);
	ptr->wsabuf.len = len;
	ptr->sendbuflen = 0;//已发送长度为0
	ptr->wsabuf.buf = (char*)malloc(len * sizeof(char));
	ptr->buf = ptr->wsabuf.buf;
	memcpy(ptr->wsabuf.buf, buf, len);
	ptr->addr = recv->addr;

	ptr->socket = recv->socket;
	ptr->OperationType = 发送数据;
	ptr->Extra = recv->Extra;
	ptr->Callback = recv->Callback;
	memset(&ptr->overlapped, 0, sizeof(OVERLAPPED));
	DWORD iFlag = 0;
	int ret = WSASend(ptr->socket, &ptr->wsabuf, 1, NULL, iFlag, (LPWSAOVERLAPPED)&ptr->overlapped, 0);
	if (ret == SOCKET_ERROR){
		ret = WSAGetLastError();
		if (ret != WSA_IO_PENDING){
			Callback funCall = (Callback)recv->Callback;
			//成功启动一个重叠操作，过后将有完成指示。
			char err[256];
			sprintf(err, "WSASend failed with Code: %d.", ret);
			recv->errInfo = err;
			funCall(发生错误, 0, 0, recv);
			recv->errInfo = 0;
			printf("send packet error: %d\n", ret);
			return -2;
		}
	}
	//printf("sended len: %d\n", getLen);
	return 0;


	
}

/*
* 关闭链接
*/
int Close(OverlappedP* recv){


	if (recv->socket == INVALID_SOCKET || recv->socket == SOCKET_ERROR){
		return -1;
	}
	int ret = 0;
	ret = shutdown(recv->socket, SD_SEND);
	if (ret == SOCKET_ERROR){
		return -2;
	}
	ret = closesocket(recv->socket);
	if (ret == SOCKET_ERROR){
		return -3;
	}
	recv->socket = SOCKET_ERROR;
	return ret;
}

void Destory(){
	if (hIocp > 0){
		PostQueuedCompletionStatus(hIocp, 0, 0, 0);
		CloseHandle(hIocp);
	}
}
