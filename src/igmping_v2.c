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

#include "igmping_v2.h"

#define _POSIX_C_SOURCE 200112L

void init_query_v2(struct igmp_query_v2 *query)
{
	assert(query != NULL);

	memset(query, 0U, sizeof(struct igmp_query_v2));
}

void set_query_v2_max_resp_time(struct igmp_query_v2 *query, unsigned char max_resp_time)
{
	assert(query != NULL);

	query->max_resp_time = max_resp_time;
}

void set_query_v2_group_address(struct igmp_query_v2 *query, const char group_address[])
{
	assert(query != NULL);
	assert(group_address != NULL);

	string_to_ip_address(&query->group_address, group_address);
}

void set_query_v2_group_address_struct(struct igmp_query_v2 *query, const struct ipv4_address *group_address)
{
	assert(query != NULL);
	assert(group_address != NULL);

	query->group_address = *group_address;
}

/*
 * returns:
 * pointer to malloc'd query data
 */
unsigned char *create_query_v2(const struct igmp_query_v2 *query)
{
	unsigned char *tmp = NULL;
	unsigned char chk_h = 0U;
	unsigned char chk_l = 0U;

	assert(query != NULL);

	tmp = malloc(8);
	assert(tmp != NULL);

	memset(tmp, 0U, 8);

	/* serialise header values except checksum */
	tmp[0] = 0x11;	/* type */
	tmp[1] = query->max_resp_time;	/* max resp time */
	tmp[4] = query->group_address.octetts[0];	/* group address */
	tmp[5] = query->group_address.octetts[1];
	tmp[6] = query->group_address.octetts[2];
	tmp[7] = query->group_address.octetts[3];

	/* calculate checksum */
	calculate_checksum(&chk_h, &chk_l, tmp, 8U);
	tmp[2] = chk_h;
	tmp[3] = chk_l;

	return tmp;
}

void init_report_v2(struct igmp_report_v2 *report)
{
	assert(report != NULL);

	memset(report, 0U, sizeof(struct igmp_report_v2));
}

void set_report_v2_group_address(struct igmp_report_v2 *report, unsigned int group_address)
{
	assert(report != NULL);

	int_to_ipv4_address(&report->group_address, group_address);
}

/*
 * returns:
 * -1 ... IGMPv2 report invalid (e. g. too short)
 * 0 ... IGMPv2 report valid
 */
int parse_report_v2(struct igmp_report_v2 *report, const unsigned char raw_message[], size_t raw_message_len, const char **error_string)
{
	unsigned int addr = 0U;

	assert(report != NULL);
	assert(raw_message != NULL);
	assert(error_string != NULL);

	if (raw_message_len < 8U)
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return -1;
	}

	init_report_v2(report);

	/* parse group address */
	addr = ((unsigned int) raw_message[4] << 24U);
	addr = addr + ((unsigned int) raw_message[5] << 16U);
	addr = addr + ((unsigned int) raw_message[6] << 8U);
	addr = addr + ((unsigned int) raw_message[7]);
	set_report_v2_group_address(report, addr);

	return 0;
}

void init_leave_group_v2(struct igmp_leave_group_v2 *leave)
{
	assert(leave != NULL);

	memset(leave, 0U, sizeof(struct igmp_leave_group_v2));
}

void set_leave_group_v2_group_address(struct igmp_leave_group_v2 *leave, unsigned int group_address)
{
	assert(leave != NULL);

	int_to_ipv4_address(&leave->group_address, group_address);
}

/*
 * returns:
 * -1 ... IGMPv2 leave group invalid (e. g. too short)
 * 0 ... IGMPv2 leave group valid
 */
int parse_leave_group_v2(struct igmp_leave_group_v2 *leave, const unsigned char raw_message[], size_t raw_message_len, const char **error_string)
{
	unsigned int addr = 0U;

	assert(leave != NULL);
	assert(raw_message != NULL);
	assert(error_string != NULL);

	if (raw_message_len < 8U)
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return -1;
	}

	init_leave_group_v2(leave);

	/* parse group address */
	addr = ((unsigned int) raw_message[4] << 24U);
	addr = addr + ((unsigned int) raw_message[5] << 16U);
	addr = addr + ((unsigned int) raw_message[6] << 8U);
	addr = addr + ((unsigned int) raw_message[7]);
	set_leave_group_v2_group_address(leave, addr);

	return 0;
}
