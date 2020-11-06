//Synopsis:
//Multiplexes ICMP requests (pings) to a large number of IPv4 addresses in an input file, quickly outputting which hosts are available.
//On UNIX, will typically need to be run with high privileges.

//Compilation:
//See make_ping_spray_unix.sh


#define FD_SETSIZE 1

#include <string>
#include <cstring>
#include <map>
#include <list>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
//#include <time>
#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <unistd.h>

#include "endian.h"

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
	unsigned char i_type;
	unsigned char i_code;
	unsigned short i_cksum;
	unsigned short i_id;
	unsigned short i_seq;
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

unsigned int ConvertInt4(unsigned int l)
{
#ifdef BIGENDIAN
	l = ((l & 0xFF) << 24) + ((l & 0xFF00) << 8) + ((l & 0xFF0000) >> 8) + (l >> 24);
#endif
	return l;
}

unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned int cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	
	return (unsigned short)(~cksum);
}

// Default parameters
int timeoutS = 3;
unsigned int pingIntervalMs = 3;
int ttl = 30;
int pings = 1;

int recvSock = -1;
std::map<unsigned int, std::string> ip2hostname;
std::map<unsigned int, unsigned int> ip2result;
bool sendsFinished = false;
bool listenerReady = false;

pthread_mutex_t mt = PTHREAD_MUTEX_INITIALIZER;

bool get_true(bool* var)
{
	bool ret;
	pthread_mutex_lock(&mt);
	ret = *var;
	pthread_mutex_unlock(&mt);
	return ret;
}

void set_true(bool* var)
{
	pthread_mutex_lock(&mt);
	*var = true;
	pthread_mutex_unlock(&mt);
}

void* listener(void* param)
{
	time_t sendsFinishedTime = 0;
	struct sockaddr_in from, local;
	socklen_t namelen = sizeof(struct sockaddr_in);
	char recvBuf[MAX_PACKET];
	fd_set recvSet;
	struct timeval selectWait;
	std::map<unsigned int, unsigned int>::iterator ip2result_it;
	int pendingResponses = ip2result.size();
	int bytesReceived;
	int ipHeaderSize;
	unsigned char type;

	if ((recvSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) return (void*)20;

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;

	if (bind(recvSock, (sockaddr*)&local, namelen) < 0) return (void*)21;
	
	set_true(&listenerReady);

	for (;;)
	{
		FD_ZERO(&recvSet);
		FD_SET(recvSock, &recvSet);

		selectWait.tv_sec = 1;
		selectWait.tv_usec = 0;

		int selectReturn = select(recvSock + 1, &recvSet, NULL, NULL, &selectWait);
						
		if (selectReturn < 0)
		{
			return (void*)23;
		}
		else if (selectReturn != 0)
		{
			if ((bytesReceived = recvfrom(recvSock, recvBuf, MAX_PACKET, 0, (sockaddr*)&from, &namelen)) < 0) return (void*)24;

			// http://en.wikipedia.org/wiki/IPv4
			ipHeaderSize = (*recvBuf & 0xF) * 4;			
			
			IcmpHeader* recvIcmpHdr = (IcmpHeader*)(recvBuf + ipHeaderSize);

			type = (bytesReceived >= (int)(ipHeaderSize + ICMP_HEADER_SIZE)) ? recvIcmpHdr->i_type : ICMP_BAD_PACKET;

			// In these 2 "proxied" cases, target IP can be retrieved from the body of the ICMP packet,
			// which is just the original IP header of the request (plus the first 8 bytes of the original body) - so 16 bytes in 
			// RFC 792
			if ((type == ICMP_DEST_UNREACH) || (type == ICMP_TTL_EXPIRE))
			{
				if (bytesReceived >= (int)(ipHeaderSize + ICMP_HEADER_SIZE + 20))
#if defined (__sun)
					from.sin_addr.S_un.S_addr = ConvertInt4(*((unsigned int*)(recvBuf + ipHeaderSize + ICMP_HEADER_SIZE + 16)));
#else
					from.sin_addr.s_addr = ConvertInt4(*((unsigned int*)(recvBuf + ipHeaderSize + ICMP_HEADER_SIZE + 16)));
#endif
				else
					type = ICMP_BAD_PACKET;
			}

			// Un-comment to report incoming packets
			//printf("Received from %s: totalBytes=%d, headerBytes = %d, type=%d\n", inet_ntoa(from.sin_addr), bytesReceived, ipHeaderSize, type);
			
			// Un-comment to dump incoming packets
			//for (int i = 0; i < bytesReceived; i++) printf("%d:%d\n", i, *((unsigned char*)recvBuf + i));

			if (type != ICMP_ECHO) // Ignore incoming echo requests (filtered out by the NIC anyway?)
			{
#if defined (__sun)
				ip2result_it = ip2result.find(from.sin_addr.S_un.S_addr); // Ignore IP addresses out of the scope of this run
#else
				ip2result_it = ip2result.find(from.sin_addr.s_addr); // Ignore IP addresses out of the scope of this run
#endif
				if (ip2result_it != ip2result.end())
				{
					if (ip2result_it->second != ICMP_ECHO_REPLY) // Check a good response is not being overwritten
					{
						if (ip2result_it->second == ICMP_NO_REPLY) pendingResponses--;
#if defined (__sun)						
						ip2result[from.sin_addr.S_un.S_addr] = type;
#else
						ip2result[from.sin_addr.s_addr] = type;
#endif						
						if (pendingResponses == 0) return (void*)0;
					}
				}
			}
		}

		if (sendsFinishedTime == 0)
		{
			if (get_true(&sendsFinished)) time(&sendsFinishedTime);
		}
		else
		{
			if (time(NULL) - sendsFinishedTime >= timeoutS) return (void*)0;
		}
	}

	return (void*)25;
}

int Usage()
{
	fprintf(stderr, "\nping_spray Copyright Solent Technology 2012\n\nUsage:\n\n");
	fprintf(stderr, "ping_spray HOST_FILE [PING_INTERVAL_MS] [TIMEOUT_S] [TTL] [PINGS]\n\n");
	fprintf(stderr, "Defaults:\n\nPING_INTERVAL_MS=%u, TIMEOUT_S=%d, TTL=%d, PINGS=%d\n\n",
		pingIntervalMs, timeoutS, ttl, pings);
	return 1;
}

int main(int argc, char* argv[])
{
	int sendSock = -1;
	struct sockaddr_in dest;
	IcmpHeader sendBuf;
	unsigned int addr = 0;
	pthread_t listenerHandle;
	std::map<unsigned int, std::string>::iterator ip2hostname_it;
	std::map<unsigned int, unsigned int>::iterator ip2result_it;
	std::list<unsigned int> ip;
	std::list<unsigned int>::iterator ip_it;
	std::list<unsigned int> failedSends;
	std::list<unsigned int>::iterator failedSends_it;
	char line[1001];
	int length;
	char* ptr1;
	char* ptr2;
	int rc = 0;
	void* listenerRc;
	struct timeval small_wait;

	try
	{
		if ((argc < 2) || (argc > 6)) return Usage();
		if (argc > 2) pingIntervalMs = atoi(argv[2]);
		if (argc > 3) timeoutS = atoi(argv[3]);
		if (argc > 4) ttl = atoi(argv[4]);
		if (argc > 5) pings = atoi(argv[5]);
		if (pings == 0) pings = 1;

		// Look for valid IP address as first token on each line in input file, and accept next token on line as hostname (if defined)
		ifstream infile(argv[1], ios::in);// | ios::nocreate);
		while (! infile.fail())
		{
			infile.getline(line, 1000, '\n');
			length = strlen(line);
			
			ptr1 = line + strspn(line, " \t");
			ptr2 = ptr1 + strcspn(line, " \t");
			*ptr2 = 0;

			memset(&dest, 0, sizeof(dest));
			dest.sin_family = AF_INET;
#if defined (__sun)
			if (((dest.sin_addr.s_addr = inet_addr(ptr1)) == (in_addr_t)(-1)) || (dest.sin_addr.S_un.S_addr == 0)) continue;
#else
			if (((dest.sin_addr.s_addr = inet_addr(ptr1)) == (in_addr_t)(-1)) || (dest.sin_addr.s_addr == 0)) continue;
#endif
			ptr1 = ptr2 + 1;
			if (ptr1 <= line + length)
			{
				ptr2 = ptr1 + strspn(ptr1, " \t");
				ptr1 = ptr2 + strcspn(ptr2, " \t");
				*ptr1 = 0;
			}
#if defined (__sun)
			ip2result[dest.sin_addr.S_un.S_addr] = ICMP_NO_REPLY;
			ip2hostname[dest.sin_addr.S_un.S_addr] = ptr2;
			ip.push_front(dest.sin_addr.S_un.S_addr);
#else
			ip2result[dest.sin_addr.s_addr] = ICMP_NO_REPLY;
			ip2hostname[dest.sin_addr.s_addr] = ptr2;
			ip.push_front(dest.sin_addr.s_addr);
#endif
		}

		if (ip.size() == 0)
		{
			fprintf(stderr, "\nError: no IP addresses found in file %s\n", argv[1]);
			return 15;
		}
	
		if ((sendSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) throw 3;
	
		if (setsockopt(sendSock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) < 0) throw 18;

		if (pthread_create(&listenerHandle, NULL, listener, 0) != 0) throw 6;

		sendBuf.i_type = ICMP_ECHO;
		sendBuf.i_code = 0;
		sendBuf.i_cksum = 0;
		sendBuf.i_seq = 1;
		sendBuf.i_id = (unsigned short)getpid();
		sendBuf.i_cksum = checksum((unsigned short*)&sendBuf, ICMP_HEADER_SIZE);
		
		// Wait for listener initialisation, in case ping replies come in before thread was in a listening state
		int listenerReadyWait = 0;
		for (;;)
		{
			if (listenerReadyWait++ > 100) throw 19;
			if (get_true(&listenerReady)) break;
			small_wait.tv_sec = 0;
			small_wait.tv_usec = 50000;
			select(0, NULL, NULL, NULL, &small_wait);
		}
	
		for (int ping = 0; ping < pings; ping++)
		{
			for (ip_it = ip.begin(); ip_it != ip.end(); ip_it++)
			{
				memset(&dest, 0, sizeof(dest));
				dest.sin_family = AF_INET;
#if defined (__sun)
				dest.sin_addr.S_un.S_addr = *ip_it;
#else
				dest.sin_addr.s_addr = *ip_it;
#endif
				if (sendto(sendSock, (const char*)&sendBuf, ICMP_HEADER_SIZE, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
				{
#if defined (__sun)
					failedSends.push_front(dest.sin_addr.S_un.S_addr);
#else
					failedSends.push_front(dest.sin_addr.s_addr);
#endif
				}

				// To prevent high cpu / network usage (?)
				small_wait.tv_sec = pingIntervalMs / 1000;
				small_wait.tv_usec = (pingIntervalMs % 1000) * 1000;
				select(0, NULL, NULL, NULL, &small_wait);
			}
		}

		set_true(&sendsFinished);
		
		if (pthread_join(listenerHandle, &listenerRc) != 0) throw 11;
		
		if (listenerRc != 0) throw (int)(intptr_t)listenerRc;

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
#if defined (__sun)
			dest.sin_addr.S_un.S_addr = addr;
#else
			dest.sin_addr.s_addr = addr;
#endif	
			printf("%s [%s] : %s\n", hostname, inet_ntoa(dest.sin_addr), response);
		}
	}
	catch (int except)
	{
		fprintf(stderr, "\nProgram failed, exit code %d, system error %d\n\n", except, errno);
		rc = except;
	}

	return rc;
}
