/*
 * igmping - IGMP message generator and sniffer
 * Copyright 2015 Peter Krebs

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "igmping_socket.h"

int open_send_socket(int *sock_desc, enum igmp_version version, const char **error_string)
{
	int status = 0;
	int sd = -1;
	int on = 1;
	int off = 0;

	assert(sock_desc != NULL);
	assert(error_string != NULL);

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (sd < 0)
	{
		switch (errno)
		{
			case EACCES:
			case EPERM:
				*error_string = SOCK_ERROR_PERM;
				break;
			default:
				*error_string = SOCK_ERROR_CREATE;
				break;
		}

		return -1;
	}

	/* we build the IP header by ourselves so set the hdrincl option */
	status = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	if (status < 0)
	{
		return -1;
	}

	/* turn off MC looping, so host does not respond to own queries */
	status = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off));
	if (status < 0)
	{
		return -1;
	}

	*sock_desc = sd;

	return 0;
}

int open_receive_socket(int *sock_desc, const char **error_string)
{
	int status = 0;
	int sd = -1;
	struct packet_mreq mreq;

	assert(sock_desc != NULL);
	assert(error_string != NULL);

	sd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sd < 0)
	{
		switch (errno)
		{
			case EACCES:
			case EPERM:
				*error_string = SOCK_ERROR_PERM;
				break;
			default:
				*error_string = SOCK_ERROR_CREATE;
				break;
		}

		return -1;
	}

	/* configure socket to accept all MC groups */
	memset(&mreq, 0, sizeof(struct packet_mreq));
	mreq.mr_ifindex = 0;
	mreq.mr_type = PACKET_MR_ALLMULTI;

	status = setsockopt(sd, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(struct packet_mreq));
	if (status < 0)
	{
		*error_string = SOCK_ERROR_SETMEMBER;
		return -1;
	}

	*sock_desc = sd;

	return 0;
}

int send_message(int socket_desc, const char destination_address[], const unsigned char raw_message[], size_t raw_message_len, enum igmp_version igmp_ver)
{
	int status = 0;
	struct addrinfo *addrp = NULL;
	struct addrinfo hints;
	ssize_t sendlen = 0;
	unsigned char hdrbuf[24] = {0x00};
	unsigned char packlen = 0U;
	size_t hdrlen = 0U;
	struct msghdr msg;
	struct iovec vec[2];
	struct ipv4_address destaddr;

	assert(destination_address != NULL);
	assert(raw_message != NULL);

	memset(&msg, 0, sizeof(struct msghdr));

	/* build IP header according to version */
	if (IGMP_V1 == igmp_ver)
	{
		hdrbuf[0] = 0x45;
		packlen = 20U + raw_message_len;
		hdrlen = 20U;
	}
	else
	{
		hdrbuf[0] = 0x46;
		packlen = 24U + raw_message_len;
		hdrbuf[20] = 0x94;
		hdrbuf[21] = 0x04;
		hdrlen = 24U;

		if (IGMP_V3 == igmp_ver)
		{
			hdrbuf[1] = 0xC0;
		}
	}

	hdrbuf[2] = packlen >> 8U;
	hdrbuf[3] = packlen;
	hdrbuf[8] = 0x01;
	hdrbuf[9] = 0x02;

	if (string_to_ip_address(&destaddr, destination_address) != 0)
	{
		return -1;
	}

	hdrbuf[16] = destaddr.octetts[0];
	hdrbuf[17] = destaddr.octetts[1];
	hdrbuf[18] = destaddr.octetts[2];
	hdrbuf[19] = destaddr.octetts[3];

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;

	status = getaddrinfo(destination_address, 0, &hints, &addrp);
	if (status < 0)
	{
		return -1;
	}

	vec[0].iov_base = hdrbuf;
	vec[0].iov_len = hdrlen;

	vec[1].iov_base = raw_message;
	vec[1].iov_len = raw_message_len;

	msg.msg_name = addrp->ai_addr;
	msg.msg_namelen = addrp->ai_addrlen;
	msg.msg_iov = vec;
	msg.msg_iovlen = 2;

	sendlen = sendmsg(socket_desc, &msg, 0);
	if ((sendlen < 0) || ((size_t) sendlen) != packlen)
	{
		return -1;
	}

	return 0;
}

/* -1 ... receive error
 * 0 ... valid ip message received
 * 1 ... invalid ip message or no igmp/multicast message received */
int receive_message(int socket_desc, struct ip_receive_info *receive_info, unsigned char raw_message[], size_t *raw_message_len)
{
	ssize_t recbytes = 0;
	unsigned char recbuf[RECBUF_SIZE];
	unsigned char hlen = 0U;
	unsigned int srcaddr = 0U;
	unsigned int dstaddr = 0U;

	assert(receive_info != NULL);
	assert(raw_message != NULL);
	assert(raw_message_len != NULL);

	memset(receive_info, 0, sizeof(struct ip_receive_info));

	recbytes = recv(socket_desc, recbuf, sizeof(recbuf), 0);
	if (recbytes < 0)
	{
		return -1;
	}

	if (recbytes < 20)
	{
		/* minium ip header size not reached */
		return 1;
	}

	/* get ip header data */
	hlen = (recbuf[0] & 0x0F) << 2U;	/* IHL */
	if (hlen > recbytes)
	{
		return 1;
	}

	if (recbuf[9] != IPPROTO_IGMP)		/* protocol */
	{
		return 1;
	}

	srcaddr = (unsigned int) recbuf[12] << 24U;	/* source address */
	srcaddr += (unsigned int) recbuf[13] << 16U;
	srcaddr += (unsigned int) recbuf[14] << 8U;
	srcaddr += (unsigned int) recbuf[15];

	int_to_ipv4_address(&receive_info->source_address, srcaddr);

	dstaddr = (unsigned int) recbuf[16] << 24U;	/* destination address */
	dstaddr += (unsigned int) recbuf[17] << 16U;
	dstaddr += (unsigned int) recbuf[18] << 8U;
	dstaddr += (unsigned int) recbuf[19];

	int_to_ipv4_address(&receive_info->destination_address, dstaddr);

	if (! is_multicast_ip_address(&receive_info->destination_address))
	{
		return 1;
	}

	receive_info->ttl = recbuf[8];	/* TTL */

	/* copy IGMP payload only to caller */
	memcpy(raw_message, &recbuf[hlen], (recbytes - hlen));
	*raw_message_len = recbytes - hlen;

	return 0;
}

#define _POSIX_C_SOURCE 200112L

