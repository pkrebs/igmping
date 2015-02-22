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

#ifndef IGMPING_V2_H_
#define IGMPING_V2_H_

#include "igmping_common.h"

#define _POSIX_C_SOURCE 200112L

struct igmp_query_v2
{
	unsigned char max_resp_time;
	struct ipv4_address group_address;
};

struct igmp_report_v2
{
	struct ipv4_address group_address;
};

struct igmp_leave_group_v2
{
	struct ipv4_address group_address;
};

void init_query_v2(struct igmp_query_v2 *query);
void set_query_v2_max_resp_time(struct igmp_query_v2 *query, unsigned char max_resp_time);
void set_query_v2_group_address(struct igmp_query_v2 *query, const char group_address[]);
void set_query_v2_group_address_struct(struct igmp_query_v2 *query, const struct ipv4_address *group_address);
unsigned char *create_query_v2(const struct igmp_query_v2 *query);

void init_report_v2(struct igmp_report_v2 *report);
void set_report_v2_group_address(struct igmp_report_v2 *report, unsigned int group_address);
int parse_report_v2(struct igmp_report_v2 *report, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);

void init_leave_group_v2(struct igmp_leave_group_v2 *leave);
void set_leave_group_v2_group_address(struct igmp_leave_group_v2 *leave, unsigned int group_address);
int parse_leave_group_v2(struct igmp_leave_group_v2 *leave, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);

#endif /* IGMPING_V2_H_ */
