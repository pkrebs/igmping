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

#ifndef IGMPING_SOCKET_H_
#define IGMPING_SOCKET_H_

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "igmping_common.h"

#define _POSIX_C_SOURCE 200112L

/* size of report receive buffer in byte */
#define RECBUF_SIZE 65535U

#define SOCK_ERROR_CREATE "could not create socket descriptor"
#define SOCK_ERROR_PERM "permission to create socket denied"
#define SOCK_ERROR_SETMEMBER "could not set all multicast membership"

struct ip_receive_info
{
	struct ipv4_address source_address;
	struct ipv4_address destination_address;
	unsigned char ttl;
};

int open_send_socket(int *sock_desc, enum igmp_version version, const char **error_string);
int open_receive_socket(int *sock_desc, const char **error_string);
int send_message(int socket_desc, const char destination_address[], const unsigned char raw_message[], size_t raw_message_len, enum igmp_version igmp_ver);
int receive_message(int socket_desc, struct ip_receive_info *receive_info, unsigned char raw_message[], size_t *raw_message_len);

#endif /* IGMPING_SOCKET_H_ */
