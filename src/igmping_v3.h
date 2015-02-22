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

#ifndef IGMPING_V3_H_
#define IGMPING_V3_H_

#include "igmping_common.h"

#define _POSIX_C_SOURCE 200112L

#define PARSE_ERROR_INVALID_RECORD_TYPE "invalid group record type"

struct source_address_node
{
	struct ipv4_address address;
	struct source_address_node *next;
};

struct source_address_list
{
	struct source_address_node *head;
	struct source_address_node *tail;
	unsigned int list_len;
};

struct igmp_query_v3
{
	unsigned char max_resp_code;
	struct ipv4_address group_address;
	unsigned char s_qrv_flags;
	unsigned char qqic;
	unsigned int number_of_sources;
	struct source_address_list source_list;
};

struct igmp_group_record_v3
{
	unsigned char record_type;
	unsigned int number_of_sources;
	struct ipv4_address mc_address;
	struct source_address_list source_list;
};

struct group_record_v3_node
{
	struct igmp_group_record_v3 record;
	struct group_record_v3_node *next;
};

struct group_record_v3_list
{
	struct group_record_v3_node *head;
	struct group_record_v3_node *tail;
};

struct igmp_report_v3
{
	unsigned int number_of_records;
	struct group_record_v3_list record_list;
};

void init_source_address_list(struct source_address_list *list);
void free_source_address_list(struct source_address_list *list);
void source_address_list_add(struct source_address_list *list, unsigned int source_address);
void source_address_list_add_struct(struct source_address_list *list, struct ipv4_address source_address);
struct ipv4_address source_address_list_get(const struct source_address_list *list, size_t index);
struct source_address_list source_address_list_clone(const struct source_address_list *list);
unsigned int source_address_list_get_length(const struct source_address_list *list);

void init_query_v3(struct igmp_query_v3 *query);
void free_query_v3(struct igmp_query_v3 *query);
void set_query_v3_max_resp_code(struct igmp_query_v3 *query, unsigned int max_resp_code);
void set_query_v3_s_flag(struct igmp_query_v3 *query);
void unset_query_v3_s_flag(struct igmp_query_v3 *query);
void set_query_v3_qrv_field(struct igmp_query_v3 *query, unsigned char qrv);
void set_query_v3_qqic_field(struct igmp_query_v3 *query, unsigned int qqic);
void set_query_v3_group_address(struct igmp_query_v3 *query, const char group_address[]);
void set_query_v3_add_source_address(struct igmp_query_v3 *query, const char source_address[]);
void set_query_v3_group_address_struct(struct igmp_query_v3 *query, const struct ipv4_address *group_address);
void set_query_v3_add_source_address_struct(struct igmp_query_v3 *query, const struct ipv4_address *source_address);
unsigned char *create_query_v3(const struct igmp_query_v3 *query, size_t *query_raw_len);

void init_group_record_v3(struct igmp_group_record_v3 *record);
void free_group_record_v3(struct igmp_group_record_v3 *record);
void set_group_record_v3_record_type(struct igmp_group_record_v3 *record, unsigned char record_type);
void set_group_record_v3_mc_address(struct igmp_group_record_v3 *record, unsigned int mc_address);
void set_group_record_v3_add_source_address(struct igmp_group_record_v3 *record, unsigned int source_address);
int parse_group_record_v3(struct igmp_group_record_v3 *record, size_t *record_len, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);

void init_group_record_v3_list(struct group_record_v3_list *list);
void free_group_record_v3_list(struct group_record_v3_list *list);
void group_record_v3_list_add(struct group_record_v3_list *list, const struct igmp_group_record_v3 *record);
struct igmp_group_record_v3 group_record_v3_list_get(const struct group_record_v3_list *list, size_t index);

void init_report_v3(struct igmp_report_v3 *report);
void free_report_v3(struct igmp_report_v3 *report);
void set_report_v3_add_group_record(struct igmp_report_v3 *report, const struct igmp_group_record_v3 *record);
int parse_report_v3(struct igmp_report_v3 *report, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);

#endif /* IGMPING_V3_H_ */
