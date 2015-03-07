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

#ifndef IGMPING_COMMON_H_
#define IGMPING_COMMON_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define _POSIX_C_SOURCE 200112L

/* default value of receive timeout in multiples of 100ms  */
#define DEFAULT_TIMEOUT 100U

/* default value of Max Resp Time/Code field in v2/v3 queries */
#define DEFAULT_MAXRESP 100U

#define PARSE_ERROR_CHKSUM_FAILED "checksum invalid"
#define PARSE_ERROR_TOO_SHORT "message too short"
#define PARSE_ERROR_INV_MSGLEN "message length invalid"
#define PARSE_ERROR_UNKNOWN_TYPE "unknown message type"

enum igmp_version {	IGMP_V1 = 1,
					IGMP_V2,
					IGMP_V3
};

enum igmp_message_type {	IGMP_INVALID = 0,
							IGMP_QUERY_V1,
							IGMP_QUERY_V2,
							IGMP_QUERY_V3,
							IGMP_REPORT_V1,
							IGMP_REPORT_V2,
							IGMP_REPORT_V3,
							IGMP_LEAVE_V2
};

enum boolean_flag { FALSE = 0,
					TRUE = 1
};

struct ipv4_address
{
	unsigned char octetts[4];
};

void get_deadline(struct timespec *deadline, const struct timespec *waittime);
int get_remaining_time(struct timespec *remaining_time, const struct timespec *deadline);

int is_unicast_ip_address(const struct ipv4_address *address);
int is_multicast_ip_address(const struct ipv4_address *address);

void int_to_ipv4_address(struct ipv4_address *address, unsigned int address_int);
void ip_address_to_string(char ip_string[], const struct ipv4_address *address);
int string_to_ip_address(struct ipv4_address *address, const char ip_string[]);
void print_ipv4_address(const struct ipv4_address *address);

void calculate_checksum(unsigned char *checksum_high_byte, unsigned char *checksum_low_byte, const unsigned char *msg_raw, size_t msg_len);
int verify_checksum(const unsigned char raw_message[], size_t raw_message_len);

#endif /* IGMPING_COMMON_H_ */
