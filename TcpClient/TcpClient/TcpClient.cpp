// TcpClient.cpp : �������̨Ӧ�ó������ڵ㡣
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
/// �궨��
#define �������� 1
#define ���ݵ��� 2
#define ���ӶϿ� 3
#define �������� 4


typedef struct OverlappedP{
	WSAOVERLAPPED overlapped;
	SOCKET socket;
	int OperationType;
	int Callback;
	WSABUF wsabuf;
	char* buf;
	DWORD sendbuflen;/*�ѷ��ͳ���*/
	sockaddr_in addr;
	int Extra;
	u_short wPort;
	char* errInfo;
}OVERLAPPEDP;


typedef int(*Callback)(int, int, int, OverlappedP*);
//��������  ���ݵ�ַ ���ݳ��� �ṹָ��

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
* ��ʼ��socket����
*/
BOOL InitWinsock(int buffersize){

	SYSTEM_INFO system;

	DWORD ThreadID;
	//����IOCP
	if ((hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0)) == NULL){
		printf("CreateIoCompletionPort failed!\n");
		return false;
	}
	//��ȡϵͳ��Ϣ
	GetSystemInfo(&system);
	//��������߳�����
	int ThreadCount = system.dwNumberOfProcessors * 2 + 2;
	for (int i = 0; i < ThreadCount; i++){
		HANDLE ThreadHandle;
		//����IOCP�߳� ����Worker
		if ((ThreadHandle = CreateThread(NULL, 0, Worker, hIocp, 0, &ThreadID)) == NULL){
			printf("CreateThread failed with error: %d\n", GetLastError());
			return false;
		}
		//�ر��߳̾��
		CloseHandle(ThreadHandle);
	}
	WSAData wsd;
	//��ʼ��winsock����
	int iResult = WSAStartup(0x0202, &wsd);
	if (iResult != 0){
		printf("WSAStartup failed with error: %d\n", iResult);
		return false;
	}
	mBuffersize = buffersize;
	return true;

}

/*
* �����߳�
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
			case ���ݵ���:
				funRecv(lpOverlapped, Transferred);
				break;
			case ��������:
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
					//�������Ͽ�: �����/�ͻ��� δ����shutdown��ֱ�ӵ���closesocket(δ����Ĵλ���).
					lpOverlapped->errInfo = "TCP connection abnormal disconnect, not completed the four wave.";//TCP�����쳣�Ͽ�, δ����Ĵλ��֡�
					if (lpOverlapped->Callback != 0){
						funCall(���ӶϿ�, 0, 0, lpOverlapped);
						free(lpOverlapped);
					}
					printf("�������Ͽ�: �����/�ͻ��� δ����shutdown��ֱ�ӵ���closesocket(δ����Ĵλ���).\n");
					break;
				case WSA_OPERATION_ABORTED://�ͻ��������Ͽ�������shutdownhour����closesocket�ͻ������������
					lpOverlapped->errInfo = "The TCP client actively closes the connection and has completed the four wave.";//TCP�����쳣�Ͽ�, δ����Ĵλ��֡�
					//TCP�ͻ��������ر����ӣ������Ѿ�����Ĵλ��֡�
					printf("�����Ͽ�: TCP�ͻ��������ر����ӣ������Ѿ�����Ĵλ���.\n");
					if (lpOverlapped->Callback != 0){
						funCall(���ӶϿ�, 0, 0, lpOverlapped);
						free(lpOverlapped);
					}
					
					//��Ϊ�׽��ֵĹرգ�һ���ص�������ȡ����������ִ����WSAIoctl()������SIO_FLUSH�������ֵ�����ڲ���ϵͳ
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
* ���ݵ���
*/
void funRecv(OverlappedP* over, DWORD Transferred){
	unsigned long iFlag = 0;
	int ret = 0;
	Callback funCall = (Callback)over->Callback;

	if (Transferred == 0){
		//1.GetQueuedCompletionStatus����ֵΪTRUE�����ʾ�ͻ����������Ͽ���TCP / IPЭ���жϿ�ʱ��4����������ˡ�
		//2.GetQueuedCompletionStatus����ֵΪFALSE�����ʾ�ͻ���������Ͽ���4������ֻ�����һ���֡�SOCKET�����Ϊ��64
		//����lpNumberOfBytes = 0, ����˶�Ҫ����ͻ��Ͽ��Ĳ�����

		//TCP���������Ͽ�, ������Ĵλ��֡�
		over->errInfo = "The TCP connection was broken normally, and the four wave was completed.";
		if (over->Callback != 0){
			funCall(���ӶϿ�, 0, 0, over);
			over->errInfo = 0;
		}
		free(over);
		printf("TCP���������Ͽ�, ������Ĵλ��֡�\n");
		return;
	}

	if (over->Callback != 0){
		funCall(���ݵ���, (int)over->wsabuf.buf, Transferred, over);
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
				funCall(��������, 0, 0, over);
				over->errInfo = 0;
				printf("%s\n", err);
				free(over);
			}
			printf("WSARecv failed!");

		}
	}

}

/*
* ���ͳɹ�
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
* �ֽ�����תʮ�������ı�
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
* ���ӷ����� ����һ���ṹָ��
*/
OverlappedP* Connect(char* serverIp, u_short serverPort, int callback, int Extra){
	struct sockaddr_in saDest;
	memset(&saDest, 0, sizeof(saDest));

	saDest.sin_addr.S_un.S_addr = inet_addr(serverIp);
	saDest.sin_port = htons(serverPort);
	saDest.sin_family = AF_INET;

	SOCKET sid = INVALID_SOCKET;
	//����socket���
	sid = socket(AF_INET, SOCK_STREAM, 0);
	if (sid == INVALID_SOCKET){
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}
	sockaddr ad;
	
	//���ӷ�����
	int ret = connect(sid, (sockaddr*)&saDest, sizeof(sockaddr));
	if (ret == SOCKET_ERROR){
		printf("connnet failed %d\n", WSAGetLastError());
		WSACleanup();
		return NULL;
	}

	//socket��iocp��
	CreateIoCompletionPort((HANDLE)sid, hIocp, sid, 0);

	OverlappedP* ptr = (OverlappedP *)malloc(sizeof(OverlappedP));
	ptr->wsabuf.len = mBuffersize;
	ptr->wsabuf.buf = (char *)malloc(mBuffersize * sizeof(char));
	ptr->OperationType = ���ݵ���;
	ptr->socket = sid;
	ptr->Callback = callback;
	ptr->Extra = Extra;
	struct sockaddr addr;
	int memlen = sizeof(sockaddr);
	//��ȡ�ͻ��˿�
	getsockname(sid, &addr, &memlen);
	sockaddr_in* addrin = (sockaddr_in *)&addr;
	ptr->wPort = addrin->sin_port;
	DWORD iFlag = 0;
	int len = sizeof(sockaddr);
	//��ʼ�ṹ �Է���ʾEvent�����Ч
	memset(&ptr->overlapped, 0, sizeof(OVERLAPPED));
	//UDP -> ret = WSARecvFrom(sid, &ptr->wsabuf, 1, &ptr->sendbuflen, &iFlag, (sockaddr *)&ptr->addr, &len, &ptr->overlapped, 0);

	//����WSARecv�ȴ���������
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
* ��ȡ����SOCKET���
*/
SOCKET GetSocket(OverlappedP* ptr){
	return ptr->socket;
}

/*
* ��ȡ�ͻ��˿�
*/
u_short GetClientPort(OverlappedP* ptr){
	return ptr->wPort;
}

/*
* ��ȡԶ�̶˿�
*/
u_short GetServerPort(OverlappedP* ptr){
	return ptr->addr.sin_port;
}

/*
* ��ȡԶ��IP��ַ
*/
int GetServerAddr(OverlappedP* ptr){
	return ptr->addr.sin_addr.S_un.S_addr;
}

/*
* ��ȡ��������
*/

int GetClientExtra(OverlappedP* ptr){
	return ptr->Extra;
}

/*
* ��ȡ������Ϣ
*/
char* GetErrInfo(OverlappedP* ptr){
	return ptr->errInfo;
}

/*
* ��������
* ����ֵ�� -1��SOCKET��Ч�� -2 ����ʧ�� ����WSAGetLastError()��ȡ�������
*/
int Send(OverlappedP* recv, char* buf, int len){
	if (recv->socket == INVALID_SOCKET || recv->socket == SOCKET_ERROR){
		return -1;
	}
	

	OverlappedP* ptr = (OverlappedP*)malloc(sizeof(OverlappedP));
	printf("send ptr: %p\n", ptr);
	ptr->wsabuf.len = len;
	ptr->sendbuflen = 0;//�ѷ��ͳ���Ϊ0
	ptr->wsabuf.buf = (char*)malloc(len * sizeof(char));
	ptr->buf = ptr->wsabuf.buf;
	memcpy(ptr->wsabuf.buf, buf, len);
	ptr->addr = recv->addr;

	ptr->socket = recv->socket;
	ptr->OperationType = ��������;
	ptr->Extra = recv->Extra;
	ptr->Callback = recv->Callback;
	memset(&ptr->overlapped, 0, sizeof(OVERLAPPED));
	DWORD iFlag = 0;
	int ret = WSASend(ptr->socket, &ptr->wsabuf, 1, NULL, iFlag, (LPWSAOVERLAPPED)&ptr->overlapped, 0);
	if (ret == SOCKET_ERROR){
		ret = WSAGetLastError();
		if (ret != WSA_IO_PENDING){
			Callback funCall = (Callback)recv->Callback;
			//�ɹ�����һ���ص����������������ָʾ��
			char err[256];
			sprintf(err, "WSASend failed with Code: %d.", ret);
			recv->errInfo = err;
			funCall(��������, 0, 0, recv);
			recv->errInfo = 0;
			printf("send packet error: %d\n", ret);
			return -2;
		}
	}
	//printf("sended len: %d\n", getLen);
	return 0;


	
}

/*
* �ر�����
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
