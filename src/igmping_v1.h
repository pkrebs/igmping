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

#ifndef IGMPING_V1_H_
#define IGMPING_V1_H_

#include "igmping_common.h"

#define _POSIX_C_SOURCE 200112L

struct igmp_query_v1
{
	struct ipv4_address group_address;
};

struct igmp_report_v1
{
	struct ipv4_address group_address;
};

void init_query_v1(struct igmp_query_v1 *query);
void set_query_v1_group_address(struct igmp_query_v1 *query, const char group_address[]);
unsigned char *create_query_v1(const struct igmp_query_v1 *query);

void init_report_v1(struct igmp_report_v1 *report);
void set_report_v1_group_address(struct igmp_report_v1 *report, unsigned int group_address);
int parse_report_v1(struct igmp_report_v1 *report, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);

#endif /* IGMPING_V1_H_ */
