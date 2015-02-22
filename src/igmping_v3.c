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

#include "igmping_v3.h"

#define _POSIX_C_SOURCE 200112L

void init_source_address_list(struct source_address_list *list)
{
	assert(list != NULL);

	memset(list, 0U, sizeof(struct source_address_list));
	list->head = NULL;
	list->tail = NULL;
}

void free_source_address_list(struct source_address_list *list)
{
	struct source_address_node *tmp = NULL;
	struct source_address_node *next = NULL;

	assert(list != NULL);

	if (list->head != NULL)
	{
		tmp = list->head;

		for(;;)
		{
			next = tmp->next;

			free(tmp);

			if (NULL == next)
			{
				break;
			}

			tmp = next;
		}
	}

	memset(list, 0U, sizeof(struct source_address_list));
}

void source_address_list_add(struct source_address_list *list, unsigned int source_address)
{
	struct ipv4_address tmp;

	int_to_ipv4_address(&tmp, source_address);

	source_address_list_add_struct(list, tmp);
}

void source_address_list_add_struct(struct source_address_list *list, struct ipv4_address source_address)
{
	struct source_address_node *tmp = NULL;

	assert(list != NULL);

	tmp = malloc(sizeof(struct source_address_node));
	assert(tmp != NULL);

	tmp->address = source_address;
	tmp->next = NULL;

	if (NULL == list->head)
	{
		/* first element */
		list->head = tmp;
		list->tail = tmp;
	}
	else
	{
		/* add to end of list */
		list->tail->next = tmp;
		list->tail = tmp;
	}

	list->list_len++;
}

struct ipv4_address source_address_list_get(const struct source_address_list *list, size_t index)
{
	size_t i = 0U;
	struct source_address_node *ptr = NULL;
	struct ipv4_address tmp;

	assert(list != NULL);
	assert(list->head != NULL);

	memset(&tmp, 0U, sizeof(struct ipv4_address));

	ptr = list->head;

	for (i = 0U; i < index; i++)
	{
		if (NULL == ptr->next)
		{
			/* index out of range */
			break;
		}

		ptr = ptr->next;
	}

	tmp = ptr->address;

	return tmp;
}

struct source_address_list source_address_list_clone(const struct source_address_list *list)
{
	struct source_address_list tmp;
	struct ipv4_address addr;
	struct source_address_node *ptr = NULL;

	assert(list != NULL);

	init_source_address_list(&tmp);

	if (list->head != NULL)
	{
		/* deep copy list nodes */
		for (ptr = list->head; ptr != NULL; ptr = ptr->next)
		{
			addr = ptr->address;
			source_address_list_add_struct(&tmp, addr);
		}
	}

	tmp.list_len = list->list_len;

	return tmp;
}

unsigned int source_address_list_get_length(const struct source_address_list *list)
{
	assert(list != NULL);

	return list->list_len;
}

void init_query_v3(struct igmp_query_v3 *query)
{
	assert(query != NULL);

	memset(query, 0U, sizeof(struct igmp_query_v3));

	init_source_address_list(&query->source_list);
}

void free_query_v3(struct igmp_query_v3 *query)
{
	assert(query != NULL);

	free_source_address_list(&query->source_list);
}

unsigned char time_to_max_resp_code(unsigned int time)
{
	unsigned char tmp = 128U;
	unsigned int delta = 0U;

	if (time < 128U)
	{
		return (unsigned char) time;
	}
	else if (time < 256U)
	{
		delta = 8U;
	}
	else if (time < 512U)
	{
		delta = 16U;
		tmp = tmp | 16U;
	}
	else if (time < 1024U)
	{
		delta = 32U;
		tmp = tmp | 32U;
	}
	else if (time < 2048U)
	{
		delta = 64U;
		tmp = tmp | 48U;
	}
	else if (time < 4096U)
	{
		delta = 128U;
		tmp = tmp | 64U;
	}
	else if (time < 8192U)
	{
		delta = 256U;
		tmp = tmp | 80U;
	}
	else if (time < 16384U)
	{
		delta = 512U;
		tmp = tmp | 96U;
	}
	else
	{
		delta = 1024U;
		tmp = tmp | 112U;
	}

	tmp = tmp | ((time / delta) - 16U);

	return tmp;
}

void set_query_v3_max_resp_code(struct igmp_query_v3 *query, unsigned int max_resp_code)
{
	assert(query != NULL);

	if (max_resp_code < 1U)
	{
		max_resp_code = 1U;
	}
	else if (max_resp_code > 31744U)
	{
		max_resp_code = 31744U;
	}

	query->max_resp_code = time_to_max_resp_code(max_resp_code);
}

void set_query_v3_s_flag(struct igmp_query_v3 *query)
{
	assert(query != NULL);

	query->s_qrv_flags = query->s_qrv_flags | 8U;
}

void unset_query_v3_s_flag(struct igmp_query_v3 *query)
{
	assert(query != NULL);

	query->s_qrv_flags = query->s_qrv_flags & 247U;
}

void set_query_v3_qrv_field(struct igmp_query_v3 *query, unsigned char qrv)
{
	assert(query != NULL);

	if (qrv > 7U)
	{
		qrv = 7U;
	}

	query->s_qrv_flags = (query->s_qrv_flags & 248U) | qrv;
}

void set_query_v3_qqic_field(struct igmp_query_v3 *query, unsigned int qqic)
{
	assert(query != NULL);

	if (qqic > 31744U)
	{
		qqic = 31744U;
	}

	query->qqic = time_to_max_resp_code(qqic);
}

void set_query_v3_group_address(struct igmp_query_v3 *query, const char group_address[])
{
	assert(query != NULL);
	assert(group_address != NULL);

	string_to_ip_address(&query->group_address, group_address);
}

void set_query_v3_group_address_struct(struct igmp_query_v3 *query, const struct ipv4_address *group_address)
{
	assert(query != NULL);
	assert(group_address != NULL);

	query->group_address = *group_address;
}

void set_query_v3_add_source_address(struct igmp_query_v3 *query, const char source_address[])
{
	struct ipv4_address addr;

	assert(query != NULL);
	assert(source_address != NULL);

	string_to_ip_address(&addr, source_address);

	source_address_list_add_struct(&query->source_list, addr);

	query->number_of_sources++;
}

void set_query_v3_add_source_address_struct(struct igmp_query_v3 *query, const struct ipv4_address *source_address)
{
	assert(query != NULL);
	assert(source_address != NULL);

	source_address_list_add_struct(&query->source_list, *source_address);

	query->number_of_sources++;
}

unsigned char *create_query_v3(const struct igmp_query_v3 *query, size_t *query_raw_len)
{
	size_t msg_len = 0U;
	unsigned char *tmp = NULL;
	unsigned char i = 0U;
	unsigned char chk_h = 0U;
	unsigned char chk_l = 0U;
	struct ipv4_address addr;

	assert(query != NULL);
	assert(query_raw_len != NULL);
	assert(query->number_of_sources <= 65535);

	/* calculate size in bytes for serialised query = 12 (fixed header + (number of sources * 4) */
	msg_len = 12U + (query->number_of_sources * 4U);

	tmp = malloc(msg_len);
	assert(tmp != NULL);

	memset(tmp, 0U, msg_len);

	/* serialise header values except checksum */
	tmp[0] = 0x11;	/* type */
	tmp[1] = query->max_resp_code;	/* max resp code */
	tmp[4] = query->group_address.octetts[0];	/* group address */
	tmp[5] = query->group_address.octetts[1];
	tmp[6] = query->group_address.octetts[2];
	tmp[7] = query->group_address.octetts[3];
	tmp[8] = query->s_qrv_flags;
	tmp[9] = query->qqic;
	tmp[10] = query->number_of_sources >> 8U;
	tmp[11] = query->number_of_sources;

	/* add sources */
	for (i = 0U; i < query->number_of_sources; i++)
	{
		addr = source_address_list_get(&query->source_list, i);

		tmp[12U + (i * 4U)] = addr.octetts[0];
		tmp[12U + (i * 4U) + 1U] = addr.octetts[1];
		tmp[12U + (i * 4U) + 2U] = addr.octetts[2];
		tmp[12U + (i * 4U) + 3U] = addr.octetts[3];
	}

	/* calculate checksum */
	calculate_checksum(&chk_h, &chk_l, tmp, msg_len);
	tmp[2] = chk_h;
	tmp[3] = chk_l;

	*query_raw_len = msg_len;

	return tmp;
}

void init_group_record_v3(struct igmp_group_record_v3 *record)
{
	assert(record != NULL);

	memset(record, 0U, sizeof(struct igmp_group_record_v3));

	init_source_address_list(&record->source_list);
}

void free_group_record_v3(struct igmp_group_record_v3 *record)
{
	assert(record != NULL);

	free_source_address_list(&record->source_list);

	memset(record, 0U, sizeof(struct igmp_group_record_v3));
}

void set_group_record_v3_record_type(struct igmp_group_record_v3 *record, unsigned char record_type)
{
	record->record_type = record_type;
}

void set_group_record_v3_mc_address(struct igmp_group_record_v3 *record, unsigned int mc_address)
{
	assert(record != NULL);

	int_to_ipv4_address(&record->mc_address, mc_address);
}

void set_group_record_v3_add_source_address(struct igmp_group_record_v3 *record, unsigned int source_address)
{
	assert(record != NULL);

	source_address_list_add(&record->source_list, source_address);

	record->number_of_sources++;
}

int parse_group_record_v3(struct igmp_group_record_v3 *record, size_t *record_len, const unsigned char raw_message[], size_t raw_message_len, const char **error_string)
{
	unsigned int srcnum = 0U;
	unsigned int addr = 0U;
	size_t i = 0U;

	assert(record != NULL);
	assert(record_len != NULL);
	assert(raw_message != NULL);
	assert(error_string != NULL);

	if (raw_message_len < 8U)
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return -1;
	}

	init_group_record_v3(record);

	/* parse record type, number of sources and multicast address */
	if ((raw_message[0] < 1U) || (raw_message[0] > 6))
	{
		*error_string = PARSE_ERROR_INVALID_RECORD_TYPE;
		return -1;
	}

	set_group_record_v3_record_type(record, raw_message[0U]);

	srcnum = ((unsigned int) raw_message[2]) << 8U;
	srcnum = srcnum + raw_message[3];

	addr = ((unsigned int) raw_message[4] << 24U);
	addr = addr + ((unsigned int) raw_message[5] << 16U);
	addr = addr + ((unsigned int) raw_message[6] << 8U);
	addr = addr + ((unsigned int) raw_message[7]);
	set_group_record_v3_mc_address(record, addr);

	if (raw_message_len < (8U + (srcnum * 4U)))
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return -1;
	}

	/* parse and add source addresses */
	for (i = 0U; i < srcnum; i++)
	{
		addr = ((unsigned int) raw_message[8U + (i * 4U)] << 24U);
		addr = addr + ((unsigned int) raw_message[9U + (i * 4U)] << 16U);
		addr = addr + ((unsigned int) raw_message[10U + (i * 4U)] << 8U);
		addr = addr + ((unsigned int) raw_message[11U + (i * 4U)]);

		set_group_record_v3_add_source_address(record, addr);
	}

	*record_len = 8U + (srcnum * 4U);

	return 0;
}

void init_group_record_v3_list(struct group_record_v3_list *list)
{
	assert(list != NULL);

	memset(list, 0U, sizeof(struct group_record_v3_list));
	list->head = NULL;
	list->tail = NULL;
}

void free_group_record_v3_list(struct group_record_v3_list *list)
{
	struct group_record_v3_node *tmp = NULL;
	struct group_record_v3_node *next = NULL;

	assert(list != NULL);

	if (list->head != NULL)
	{
		tmp = list->head;

		for(;;)
		{
			next = tmp->next;

			free_group_record_v3(&tmp->record);
			free(tmp);

			if (NULL == next)
			{
				break;
			}

			tmp = next;
		}
	}

	memset(list, 0U, sizeof(struct group_record_v3_list));
}

void group_record_v3_list_add(struct group_record_v3_list *list, const struct igmp_group_record_v3 *record)
{
	struct group_record_v3_node *tmp = NULL;

	assert(list != NULL);
	assert(record != NULL);

	tmp = malloc(sizeof(struct group_record_v3_node));
	assert(tmp != NULL);

	tmp->next = NULL;

	/* make deepcopy of record */
	tmp->record.mc_address = record->mc_address;
	tmp->record.number_of_sources = record->number_of_sources;
	tmp->record.record_type = record->record_type;
	tmp->record.source_list = source_address_list_clone(&record->source_list);

	if (NULL == list->head)
	{
		/* first element */
		list->head = tmp;
		list->tail = tmp;
	}
	else
	{
		/* add to end of list */
		list->tail->next = tmp;
		list->tail = tmp;
	}
}

struct igmp_group_record_v3 group_record_v3_list_get(const struct group_record_v3_list *list, size_t index)
{
	size_t i = 0U;
	struct group_record_v3_node *ptr = NULL;
	struct igmp_group_record_v3 tmp;

	assert(list != NULL);
	assert(list->head != NULL);

	memset(&tmp, 0U, sizeof(struct igmp_group_record_v3));

	ptr = list->head;

	for (i = 0U; i < index; i++)
	{
		if (NULL == ptr->next)
		{
			/* index out of range */
			break;
		}

		ptr = ptr->next;
	}

	tmp = ptr->record;

	return tmp;
}

void init_report_v3(struct igmp_report_v3 *report)
{
	assert(report != NULL);

	memset(report, 0U, sizeof(struct igmp_report_v3));

	init_group_record_v3_list(&report->record_list);
}

void free_report_v3(struct igmp_report_v3 *report)
{
	assert(report != NULL);

	free_group_record_v3_list(&report->record_list);

	memset(report, 0U, sizeof(struct igmp_report_v3));
}

void set_report_v3_add_group_record(struct igmp_report_v3 *report, const struct igmp_group_record_v3 *record)
{
	assert(report != NULL);
	assert(record != NULL);

	group_record_v3_list_add(&report->record_list, record);
	report->number_of_records++;
}

int parse_report_v3(struct igmp_report_v3 *report, const unsigned char raw_message[], size_t raw_message_len, const char **error_string)
{
	int status = 0;
	unsigned int recnum = 0U;
	struct igmp_group_record_v3 record;
	unsigned int i = 0U;
	size_t len = 0U;
	size_t ind = 0U;

	assert(report != NULL);
	assert(raw_message != NULL);
	assert(error_string != NULL);

	if (raw_message_len < 8U)
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return -1;
	}

	init_report_v3(report);

	/* parse number of records */
	recnum = ((unsigned int) raw_message[6]) << 8U;
	recnum = recnum + raw_message[7];

	/* parse group records */
	ind = 8U;

	for (i = 0U; i < recnum; i++)
	{
		status = parse_group_record_v3(&record, &len, &raw_message[ind], (raw_message_len - ind), error_string);
		if (status != 0)
		{
			return -1;
		}

		set_report_v3_add_group_record(report, &record);
		ind = ind + len;
	}

	return 0;
}
