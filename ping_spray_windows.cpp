//Synopsis:
//Multiplexes ICMP requests (pings) to a large number of IPv4 addresses in an input file, quickly outputting which hosts are available.

//Compilation:
//cl.exe /Ox /MT /EHsc ping_spray_windows.cpp Ws2_32.lib /Fe:ping_spray.exe

#define FD_SETSIZE 1
#define WIN32_LEAN_AND_MEAN

#pragma warning(disable:4786) // identifier was truncated to '255' characters in the debug information
#pragma warning(disable:4503) // decorated name length exceeded

#include <string>
#include <map>
#include <list>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <time.h>
#include <fstream>

using namespace std;


/* Not used - just for documentation
typedef struct _iphdr
{
	unsigned int h_len:4; // Length of the header
	unsigned int version:4; // Version of IP
	unsigned char tos; // Type of service
	unsigned short total_len; // Total length of the packet
	unsigned short ident; // Unique identifier
	unsigned short frag_and_flags; // Flags
	unsigned char ttl; // Time to live
	unsigned char proto; // Protocol (TCP, UDP, etc.)
	unsigned short checksum; // IP checksum
	unsigned int sourceIP;
	unsigned int destIP;
} IpHeader;
*/

typedef struct _icmphdr
{
	BYTE i_type;
	BYTE i_code;
	USHORT i_cksum;
	USHORT i_id;
	USHORT i_seq;
} IcmpHeader;

#define ICMP_ECHO_REPLY 0		// OK
#define ICMP_DEST_UNREACH 3		// DESTINATION_UNREACHABLE
#define ICMP_ECHO 8	
#define ICMP_TTL_EXPIRE 11		// TTL_EXPIRED
#define ICMP_SEND_FAILED 248	// SEND_FAILED - this is a code I made up
#define ICMP_BAD_PACKET 249		// BAD_ICMP_PACKET - this is a code I made up
#define ICMP_NO_REPLY 250		// NO_REPLY - this is a code I made up

#define ICMP_HEADER_SIZE sizeof(IcmpHeader)
#define MAX_PACKET 1024

USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum=0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	
	return (USHORT)(~cksum);
}

// Default parameters
DWORD timeoutS = 3;
DWORD pingIntervalMs = 3;
int ttl = 30;
int pings = 1;

SOCKET recvSock = INVALID_SOCKET;
std::map<unsigned long, std::string> ip2hostname;
std::map<unsigned long, unsigned long> ip2result;
HANDLE listenerReady = NULL;
HANDLE timeout = NULL;

DWORD WINAPI listener(void* param)
{
	struct sockaddr_in from, local;
	int namelen = sizeof(struct sockaddr_in);
	char recvBuf[MAX_PACKET];
	fd_set recvSet;
	struct timeval selectWait;
	selectWait.tv_sec = 1;
	selectWait.tv_usec = 0;
	std::map<unsigned long, unsigned long>::iterator ip2result_it;
	int pendingResponses = ip2result.size();
	int bytesReceived;
	int ipHeaderSize;
	BYTE type;
		
	if ((recvSock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0)) == INVALID_SOCKET) return 20;

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;

	if (bind(recvSock, (sockaddr*)&local, namelen) == SOCKET_ERROR) return 21;

	if (! SetEvent(listenerReady)) return 22;

	for (;;)
	{
		FD_ZERO(&recvSet);
		FD_SET(recvSock, &recvSet);

		int selectReturn = select(1, &recvSet, NULL, NULL, &selectWait);

		if (selectReturn == SOCKET_ERROR)
		{
			return 23;
		}
		else if (selectReturn != 0)
		{
			if ((bytesReceived = recvfrom(recvSock, recvBuf, MAX_PACKET, 0, (sockaddr*)&from, &namelen)) == SOCKET_ERROR) return 24;

			// http://en.wikipedia.org/wiki/IPv4
			ipHeaderSize = (*recvBuf & 0xF) * 4;

			IcmpHeader* recvIcmpHdr = (IcmpHeader*)(recvBuf + ipHeaderSize);

			type = (bytesReceived >= ipHeaderSize + ICMP_HEADER_SIZE) ? recvIcmpHdr->i_type : ICMP_BAD_PACKET;

			// In these 2 "proxied" cases, target IP can be retrieved from the body of the ICMP packet,
			// which is just the original IP header of the request (plus the first 8 bytes of the original body) - so 16 bytes in 
			// RFC 792
			if ((type == ICMP_DEST_UNREACH) || (type == ICMP_TTL_EXPIRE))
			{
				if (bytesReceived >= ipHeaderSize + ICMP_HEADER_SIZE + 28)
					from.sin_addr.S_un.S_addr = *((unsigned long*)(recvBuf + ipHeaderSize + ICMP_HEADER_SIZE + 16));
				else
					type = ICMP_BAD_PACKET;
			}

			// Un-comment to report incoming packets
			//printf("Received from %s: totalBytes=%d, headerBytes = %d, type=%d\n", inet_ntoa(from.sin_addr), bytesReceived, ipHeaderSize, type);
			
			// Un-comment to dump incoming packets
			//for (int i = 0; i < bytesReceived; i++) printf("%d:%d\n", i, *((unsigned char*)recvBuf + i));

			if (type != ICMP_ECHO) // Ignore incoming echo requests (filtered out by the NIC anyway?)
			{
				ip2result_it = ip2result.find(from.sin_addr.S_un.S_addr); // Ignore IP addresses out of the scope of this run
				if (ip2result_it != ip2result.end())
				{
					if (ip2result_it->second != ICMP_ECHO_REPLY) // Check a good response is not being overwritten
					{
						if (ip2result_it->second == ICMP_NO_REPLY) pendingResponses--;
						
						ip2result[from.sin_addr.S_un.S_addr] = type;
						if (pendingResponses == 0) return 0;
					}
				}
			}
		}

		if (WaitForSingleObject(timeout, 0) == WAIT_OBJECT_0) return 0;
	}

	return 25;
}

int Usage()
{
	fprintf(stderr, "\nPING_SPRAY Copyright Solent Technology 2012\n\nUsage:\n\n");
	fprintf(stderr, "ping_spray HOST_FILE [PING_INTERVAL_MS] [TIMEOUT_S] [TTL] [PINGS]\n\n");
	fprintf(stderr, "Defaults:\n\nPING_INTERVAL_MS=%u, TIMEOUT_S=%u, TTL=%d, PINGS=%d\n\n",
		pingIntervalMs, timeoutS, ttl, pings);
	return 1;
}

int main(int argc, char* argv[])
{
	WSADATA wsaData;
	SOCKET sendSock = INVALID_SOCKET;
	struct sockaddr_in dest;
	IcmpHeader sendBuf;
	unsigned int addr = 0;
	DWORD listenerId;
	HANDLE listenerHandle;
	std::map<unsigned long, std::string>::iterator ip2hostname_it;
	std::map<unsigned long, unsigned long>::iterator ip2result_it;
	std::list<unsigned long> ip;
	std::list<unsigned long>::iterator ip_it;
	std::list<unsigned long> failedSends;
	std::list<unsigned long>::iterator failedSends_it;
	char line[1001];
	int length;
	char* ptr1;
	char* ptr2;
	int rc = 0;
	DWORD listenerRc;

	try
	{
		if ((argc < 2) || (argc > 6)) return Usage();
		if (argc > 2) pingIntervalMs = atoi(argv[2]);
		if (argc > 3) timeoutS = atoi(argv[3]);
		if (argc > 4) ttl = atoi(argv[4]);
		if (argc > 5) pings = atoi(argv[5]);
		if (pings == 0) pings = 1;

		// Look for valid IP address as first token on each line in input file, and accept next token on line as hostname (if defined)
		ifstream infile(argv[1], ios::in );
		while (! infile.fail())
		{
			infile.getline(line, 1000, '\n');
			length = strlen(line);
			
			ptr1 = line + strspn(line, " \t");
			ptr2 = ptr1 + strcspn(line, " \t");
			*ptr2 = 0;

			memset(&dest, 0, sizeof(dest));
			dest.sin_family = AF_INET;
			if (((dest.sin_addr.s_addr = inet_addr(ptr1)) == INADDR_NONE) || (dest.sin_addr.S_un.S_addr == 0)) continue;

			ptr1 = ptr2 + 1;
			if (ptr1 <= line + length)
			{
				ptr2 = ptr1 + strspn(ptr1, " \t");
				ptr1 = ptr2 + strcspn(ptr2, " \t");
				*ptr1 = 0;
			}

			ip2result[dest.sin_addr.S_un.S_addr] = ICMP_NO_REPLY;
			ip2hostname[dest.sin_addr.S_un.S_addr] = ptr2;
			ip.push_front(dest.sin_addr.S_un.S_addr);
		}

		if (ip.size() == 0)
		{
			fprintf(stderr, "\nError: no IP addresses found in file %s\n", argv[1]);
			return 15;
		}

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) throw 2;
	
		if ((sendSock = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0)) == INVALID_SOCKET) throw 3;

		if (setsockopt(sendSock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) throw 18;

		if ((listenerReady = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL) throw 4;

		if ((timeout = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL) throw 5;

		if ((listenerHandle = CreateThread(NULL, NULL, listener, NULL, NULL, &listenerId)) == NULL) throw 6;

		sendBuf.i_type = ICMP_ECHO;
		sendBuf.i_code = 0;
		sendBuf.i_cksum = 0;
		sendBuf.i_seq = 1;
		sendBuf.i_id = (USHORT)GetCurrentProcessId();
		sendBuf.i_cksum = checksum((USHORT*)&sendBuf, ICMP_HEADER_SIZE);

		// Wait for listener initialisation, in case ping replies come in before thread was in a listening state
		if (WaitForSingleObject(listenerReady, 30000) != WAIT_OBJECT_0) throw 7;

		for (int ping = 0; ping < pings; ping++)
		{
			for (ip_it = ip.begin(); ip_it != ip.end(); ip_it++)
			{
				memset(&dest, 0, sizeof(dest));
				dest.sin_family = AF_INET;

				dest.sin_addr.S_un.S_addr = *ip_it;

				if (sendto(sendSock, (const char*)&sendBuf, ICMP_HEADER_SIZE, 0, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR)
					failedSends.push_front(dest.sin_addr.S_un.S_addr);

				SleepEx(pingIntervalMs, FALSE); // To prevent high cpu / network usage (?)
			}
		}

		WaitForSingleObject(listenerHandle, timeoutS * 1000);

		if (! SetEvent(timeout)) throw 9;

		if (WaitForSingleObject(listenerHandle, 30000) != WAIT_OBJECT_0) throw 10;

		if (! GetExitCodeThread(listenerHandle, &listenerRc)) throw 11;

		if (listenerRc != 0) throw listenerRc;

		// Use list of send failures to account for missed replies
		for (failedSends_it = failedSends.begin(); failedSends_it != failedSends.end(); failedSends_it++)
		{
			ip2result_it = ip2result.find(*failedSends_it);
			if ((ip2result_it != ip2result.end()) && (ip2result_it->second == ICMP_NO_REPLY))
				ip2result[*failedSends_it] = ICMP_SEND_FAILED;
		}

		for (ip2result_it = ip2result.begin() ; ip2result_it != ip2result.end() ; ip2result_it++)
		{
			addr = ip2result_it->first;

			const char* hostname;

			ip2hostname_it = ip2hostname.find(addr);
			if (ip2hostname_it != ip2hostname.end())
				hostname = ip2hostname_it->second.c_str();
			else
				hostname = "";

			const char* response;
			switch (ip2result_it->second)
			{
				case ICMP_ECHO_REPLY:
					response = "OK";
					break;

				case ICMP_TTL_EXPIRE:
					response = "TTL_EXPIRED";
					break;

				case ICMP_DEST_UNREACH:
					response = "DESTINATION_UNREACHABLE";
					break;

				case ICMP_NO_REPLY:
					response = "NO_REPLY";
					break;

				case ICMP_BAD_PACKET:
					response = "BAD_ICMP_PACKET";
					break;

				case ICMP_SEND_FAILED:
					response = "SEND_FAILED";
					break;

				default:
					response = "UNKNOWN_ICMP_REPLY_TYPE";
			}

			dest.sin_addr.S_un.S_addr = addr;
			
			printf("%s [%s] : %s\n", hostname, inet_ntoa(dest.sin_addr), response);
		}
	}
	catch (int except)
	{
		fprintf(stderr, "\nProgram failed, exit code %d, system error %u\n\n", except, GetLastError());
		rc = except;
	}

	// These can cause hangs under some error conditions - best avoided
	//	if (sendSock != INVALID_SOCKET) closesocket(sendSock);
	//	if (recvSock != INVALID_SOCKET) closesocket(recvSock);
	//	WSACleanup();

	return rc;
}
