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

/*
 * timeout/maxresp interaction:
 * - normal mode:
 * 		- no timeout, no maxresp: default timeout, default maxresp
 * 		- timeout = 0, no maxresp: no timeout, default maxresp
 * 		- timeout > 0, no maxresp: set timeout (max 31744), maxresp = timeout (v3: same value, v2: clamped to 255, v1: default timeout)
 * 		- no timeout, maxresp set: default timeout, set maxresp (v2: max 255, v3: mac 31744)
 * 		- timeout = 0, maxresp set: no timeout, set maxresp (v2: max 255, v3: max 31744)
 * 		- timeout > 0, maxresp set: set timeout (max 31744), set maxresp
 * 	- listen mode:
 * 		- no timeout: default timeout
 * 		- timeout = 0: no timeout
 * 		- timeout > 0, set timeout (full range allowed)
 *
 *
 * todo:
 *
 * @author Peter Krebs
 */

#include "igmping.h"

#define _POSIX_C_SOURCE 200112L

/* v3: general qry: group addr = 0| destaddr = 224.0.0.1, group qry: group addr|destaddr = mc addr, group-src-qry: group addr|destaddr = mc addr, source addr list not empty
 * v2: like v3 without group-src
 * v1: groupaddr = 0, destaddr = 224.0.0.1*/
int send_igmp_query(int socket_desc, const struct ipv4_address *group_address, const struct igmp_send_options *send_options, const struct source_address_list *src_addr_list)
{
	int status = 0;
	struct igmp_query_v3 qry_v3;
	struct igmp_query_v2 qry_v2;
	struct igmp_query_v1 qry_v1;
	const char *destaddr = "224.0.0.1";
	unsigned char *raw_qry = NULL;
	size_t raw_qry_len = 0U;
	size_t i = 0U;
	unsigned int srclistlen = 0U;
	struct ipv4_address srcaddr;
	char addrbuf[INET6_ADDRSTRLEN + 1U] = "";

	assert(send_options != NULL);

	switch (send_options->version)
	{
		case IGMP_V1:
			init_query_v1(&qry_v1);
			raw_qry = create_query_v1(&qry_v1);
			assert(raw_qry != NULL);
			raw_qry_len = 8U;
			break;
		case IGMP_V2:
			init_query_v2(&qry_v2);
			set_query_v2_max_resp_time(&qry_v2, send_options->response_time);

			if (group_address != NULL)
			{
				/* group specific query */
				set_query_v2_group_address_struct(&qry_v2, group_address);
				ip_address_to_string(addrbuf, group_address);
				destaddr = addrbuf;
			}

			raw_qry = create_query_v2(&qry_v2);
			assert(raw_qry != NULL);
			raw_qry_len = 8U;
			break;
		case IGMP_V3:
			init_query_v3(&qry_v3);
			set_query_v3_max_resp_code(&qry_v3, send_options->response_time);

			if (TRUE == send_options->set_s_flag)
			{
				set_query_v3_s_flag(&qry_v3);
			}

			set_query_v3_qrv_field(&qry_v3, send_options->qrv_value);
			set_query_v3_qqic_field(&qry_v3, send_options->qqic_value);

			if (group_address != NULL)
			{
				/* group/group-source-specific query */
				set_query_v3_group_address_struct(&qry_v3, group_address);
				ip_address_to_string(addrbuf, group_address);
				destaddr = addrbuf;
			}

			if (src_addr_list != NULL)
			{
				srclistlen = source_address_list_get_length(src_addr_list);

				for (i = 0U; i < srclistlen; i++)
				{
					srcaddr = source_address_list_get(src_addr_list, i);
					set_query_v3_add_source_address_struct(&qry_v3, &srcaddr);
				}
			}

			raw_qry = create_query_v3(&qry_v3, &raw_qry_len);
			assert(raw_qry != NULL);
			break;
		default:
			return -1;
			break;
	}

	/* send via raw socket */
	status = send_message(socket_desc, destaddr, raw_qry, raw_qry_len, send_options->version);
	if (status != 0)
	{
		return -1;
	}

	free(raw_qry);

	return 0;
}

void init_receive_vector(struct igmp_receive_vector *receive_vector)
{
	assert(receive_vector != NULL);

	memset(&receive_vector->ip_info, 0, sizeof(struct ip_receive_info));

	receive_vector->message_type = IGMP_INVALID;
	init_report_v1(&receive_vector->report_v1);
	init_report_v2(&receive_vector->report_v2);
	init_report_v3(&receive_vector->report_v3);
	init_leave_group_v2(&receive_vector->leave_group_v2);
}

void free_receive_vector(struct igmp_receive_vector *receive_vector)
{
	assert(receive_vector != NULL);

	free_report_v3(&receive_vector->report_v3);
}

/* 0 ... parsed valid igmp report/leave group
 * 1 ... parsed valid igmp query
 * 2 ... parsed invalid igmp message
 * */
int process_igmp_message(struct igmp_receive_vector *receive_vector, const unsigned char raw_message[], size_t raw_message_len, const char **error_string)
{
	unsigned char msgtype = 0U;

	assert(receive_vector != NULL);
	assert(raw_message != NULL);
	assert(error_string != NULL);

	if (raw_message_len < 8U)
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return 2;
	}

	/* verify checksum */
	if (verify_checksum(raw_message, raw_message_len))
	{
		*error_string = PARSE_ERROR_TOO_SHORT;
		return 2;
	}

	/* parse according to message type */
	msgtype = raw_message[0];

	switch (msgtype)
	{
		case 0x11:	/* query, ignore */
			if (raw_message_len > 8U)
			{
				receive_vector->message_type = IGMP_QUERY_V3;
			}
			else if (raw_message[1] != 0U)
			{
				receive_vector->message_type = IGMP_QUERY_V2;
			}
			else
			{
				receive_vector->message_type = IGMP_QUERY_V1;
			}
			return 1;
			break;
		case 0x12:	/* membership report v1 */
			if (parse_report_v1(&receive_vector->report_v1, raw_message, raw_message_len, error_string) != 0)
			{
				return 2;
			}
			receive_vector->message_type = IGMP_REPORT_V1;
			break;
		case 0x16:	/* membership report v2 */
			if (parse_report_v2(&receive_vector->report_v2, raw_message, raw_message_len, error_string) != 0)
			{
				return 2;
			}
			receive_vector->message_type = IGMP_REPORT_V2;
			break;
		case 0x17:	/* leave */
			if (parse_leave_group_v2(&receive_vector->leave_group_v2, raw_message, raw_message_len, error_string) != 0)
			{
				return 2;
			}
			receive_vector->message_type = IGMP_LEAVE_V2;
			break;
		case 0x22:	/* membership report v3 */
			if (parse_report_v3(&receive_vector->report_v3, raw_message, raw_message_len, error_string) != 0)
			{
				return 2;
			}
			receive_vector->message_type = IGMP_REPORT_V3;
			break;
		default:	/* unknown type */
			*error_string = PARSE_ERROR_UNKNOWN_TYPE;
			receive_vector->message_type = IGMP_INVALID;
			return 2;
			break;
	}

	return 0;
}

/* 0 ... received valid igmp report or leave group
 * 1 ... timeout and no message received
 * 2 ... igmp message other than report or leave group received
 * 3 ... invalid or non igmp-message received
 * -1 ... receive error */
int receive_igmp_report(int socket_desc, struct igmp_receive_vector *receive_vector, const struct timespec *timeout, const char **error_string)
{
	int status = 0;
	struct timespec temp;
	struct timespec *tp = NULL;
	unsigned char recbuf[RECBUF_SIZE];
	size_t raw_msg_len = 0U;
	fd_set readset;

	assert(receive_vector != NULL);
	assert(error_string != NULL);

	memset(recbuf, 0, sizeof(recbuf));

	FD_ZERO(&readset);
	FD_SET(socket_desc, &readset);

	if (timeout != NULL)
	{
		temp = *timeout;
		tp = &temp;
	}

	status = pselect((socket_desc + 1), &readset, NULL, NULL, tp, NULL);

	if (status < 0)
	{
		return -1;
	}
	else if (0 == status)
	{
		/* receive timeout */
		return 1;
	}
	else if (! FD_ISSET(socket_desc, &readset))
	{
		return -1;
	}

	status = receive_message(socket_desc, &receive_vector->ip_info, recbuf, &raw_msg_len);
	if (-1 == status)
	{
		return -1;
	}
	else if (1 == status)
	{
		/* received invalid or no multicast/igmp message */
		return 3;
	}
	else
	{
		/* received valid ip multicast message with igmp protocol type */
		status = process_igmp_message(receive_vector, recbuf, raw_msg_len, error_string);
		if (2 == status)
		{
			/* received invalid igmp message */
			return 3;
		}
		else if (1 == status)
		{
			/* received igmp query */
			return 2;
		}
	}

	return 0;
}

void print_group_record_info(const struct igmp_group_record_v3 *group_record)
{
	assert(group_record != NULL);

	switch(group_record->record_type)
	{
		case 1:
			printf("\tRecord-Type = MODE_IS_INCLUDE\n");
			/* join for all sources in srclist OR leave when srclist empty */
			break;
		case 2:
			printf("\tRecord-Type = MODE_IS_EXCLUDE\n");
			/* leave for all sources in srclist OR join when srclist empty */
			break;
		case 3:
			printf("\tRecord-Type = CHANGE_TO_INCLUDE_MODE\n");
			break;
		case 4:
			printf("\tRecord-Type = CHANGE_TO_EXCLUDE_MODE\n");
			break;
		case 5:
			printf("\tRecord-Type = ALLOW_NEW_SOURCES\n");
			/* join for all sources in srclist */
			break;
		case 6:
			printf("\tRecord-Type = BLOCK_OLD_SOURCES\n");
			/* block for all sources in srclist */
			break;
		default:
			break;
	}

	printf("\tMulticast Address = ");
	print_ipv4_address(&group_record->mc_address);
	printf("\n");

	printf("\tSource list = ");

	if (0U == group_record->number_of_sources)
	{
		printf("{ empty }");
		switch(group_record->record_type)
		{
			case 1:
			case 3:
				printf(" (LEAVE for all sources)");
				break;
			case 2:
			case 4:
				printf(" (JOIN for all sources)");
				break;
			default:
				break;
		}

		printf("\n");
	}
}

void print_report_info(const struct igmp_receive_vector *receive_vector)
{
	unsigned int i = 0U;
	struct igmp_group_record_v3 rec;

	assert(receive_vector != NULL);

	switch(receive_vector->message_type)
	{
		case IGMP_REPORT_V1:
			printf("Received IGMPv1 Report from ");
			print_ipv4_address(&receive_vector->ip_info.source_address);
			printf(": dst=");
			print_ipv4_address(&receive_vector->ip_info.destination_address);
			printf(" ttl=%u\n", receive_vector->ip_info.ttl);
			printf("\tGroup Address (JOIN) = ");
			print_ipv4_address(&receive_vector->report_v1.group_address);
			printf("\n\n");
			break;
		case IGMP_REPORT_V2:
			printf("Received IGMPv2 Report from ");
			print_ipv4_address(&receive_vector->ip_info.source_address);
			printf(": dst=");
			print_ipv4_address(&receive_vector->ip_info.destination_address);
			printf(" ttl=%u\n", receive_vector->ip_info.ttl);
			printf("\tGroup Address (JOIN) = ");
			print_ipv4_address(&receive_vector->report_v2.group_address);
			printf("\n\n");
			break;
		case IGMP_REPORT_V3:
			printf("Received IGMPv3 Report from ");
			print_ipv4_address(&receive_vector->ip_info.source_address);
			printf(": dst=");
			print_ipv4_address(&receive_vector->ip_info.destination_address);
			printf(" ttl=%u\n", receive_vector->ip_info.ttl);
			printf("\tNumber of Group Records = %u\n", receive_vector->report_v3.number_of_records);

			for (i = 0U; i < receive_vector->report_v3.number_of_records; i++)
			{
				rec = group_record_v3_list_get(&receive_vector->report_v3.record_list, i);
				printf("\t----Record %u----\n", (i + 1U));
				print_group_record_info(&rec);
			}
			printf("\n");

			break;
		case IGMP_LEAVE_V2:
			printf("Received IGMPv2 Leave Group from ");
			print_ipv4_address(&receive_vector->ip_info.source_address);
			printf(": dst=");
			print_ipv4_address(&receive_vector->ip_info.destination_address);
			printf(" ttl=%u\n", receive_vector->ip_info.ttl);
			printf("\tGroup Address (LEAVE) = ");
			print_ipv4_address(&receive_vector->leave_group_v2.group_address);
			printf("\n\n");
			break;
		default:
			break;
	}
}

/* 0 ... received at least one valid IGMP report
 * 1 ... received no valid IGMP report until timeout
 * -1 ... receive error */
int receive_igmp_messages(int socket_desc, const struct timespec *timeout)
{
	int status = 0;
	struct igmp_receive_vector rec_vector;
	struct timespec waittime;
	struct timespec deadline;
	unsigned int received_reports = 0U;
	const char *error_string = "";

	assert(error_string != NULL);

	if (timeout != NULL)
	{
		/* calculate absolute deadline for restarts */
		get_deadline(&deadline, timeout);
	}

	for(;;)
	{
		init_receive_vector(&rec_vector);

		if (timeout != NULL)
		{
			get_remaining_time(&waittime, &deadline);

			status = receive_igmp_report(socket_desc, &rec_vector, &waittime, &error_string);
		}
		else
		{
			status = receive_igmp_report(socket_desc, &rec_vector, NULL, &error_string);
		}

		if (-1 == status)
		{
			return -1;
		}
		else if (1 == status)
		{
			break;
		}
		else if (0 == status)
		{
			print_report_info(&rec_vector);
			received_reports++;
			free_receive_vector(&rec_vector);
		}

	}

	if (0U == received_reports)
	{
		printf("\nReceived no IGMP reports\n");
		return 1;
	}

	printf("Received %u IGMP Reports\n", received_reports);

	return 0;
}

void init_options(struct parsed_options *options)
{
	assert(options != NULL);

	memset(options, 0, sizeof(struct parsed_options));

	options->query_timeout = DEFAULT_TIMEOUT;

	options->query_max_resp = DEFAULT_MAXRESP;

	options->query_version = IGMP_V2;

	init_source_address_list(&options->srcaddr_list);

	options->query_set_flag = FALSE;
}

/* 1 ... non ip address ecountered
 * 2 ... non unicast address encountered */
int parse_sourceaddr_list(struct source_address_list *srclist, const char string[])
{
	size_t slen = 0U;
	size_t i = 0U;
	size_t addrstart = 0U;
	char buf[(INET6_ADDRSTRLEN + 1U)] = {'\0'};
	struct ipv4_address ipaddr;

	assert(srclist != NULL);
	assert(string != NULL);

	init_source_address_list(srclist);

	slen = strlen(string);

	for (i = 0U; i <= slen; i++)
	{
		if ((',' == string[i]) || (i == slen))
		{
			memset(buf, 0, sizeof(buf));
			memcpy(buf, &string[addrstart], (i - addrstart));

			if (string_to_ip_address(&ipaddr, buf) != 0)
			{
				return 1;
			}

			if (! is_unicast_ip_address(&ipaddr))
			{
				return 2;
			}

			source_address_list_add_struct(srclist, ipaddr);

			addrstart = i + 1U;
		}
	}

	return 0;
}

/* 0 ... all ok
 * 1 ... parse error
 * 2 ... parse warning */
int parse_options(struct parsed_options *options, int argc, char *argv[], const char **errstring)
{
	int status = 0;
	unsigned long tmp = 0U;
	char *endptr = NULL;
	int listen_mode = 0;
	int timeout_set = 0;
	int maxresp_set = 0;

	assert(options != NULL);
	assert(argv != NULL);
	assert(errstring != NULL);

	/* disable stderr messages of getopt */
	opterr = 0;

	for (;;)
	{
		status = getopt(argc, argv, ":hvlfm:s:t:V:q:r:");
		if (-1 == status)
		{
			/* all parameters parsed */
			break;
		}

		switch (status)
		{
			case 'h':
				/* print help */
				options->opt_result = OPT_HELP;
				return 0;
				break;
			case 'f':
				/* set S flag */
				options->query_set_flag = TRUE;
				break;
			case 'm':
				/* max resp value/code, in 100ms units */
				errno = 0;
				tmp = strtoul(optarg, &endptr, 10);
				if (errno != 0)
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVMAXRESP;
					return 1;
				}
				options->query_max_resp = tmp;
				maxresp_set = 1;
				break;
			case 'l':
				/* listen mode */
				listen_mode = 1;
				break;
			case 'q':
				/* QRV value */
				errno = 0;
				tmp = strtoul(optarg, &endptr, 10);
				if ((errno != 0) || (tmp > 7U))
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVQRV;
					return 1;
				}
				options->query_qrv_value = tmp;
				break;
			case 'r':
				/* QQIC value, in 1s units */
				errno = 0;
				tmp = strtoul(optarg, &endptr, 10);
				if ((errno != 0) || (tmp > 31744U))
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVQQIC;
					return 1;
				}
				options->query_qqic_value = tmp;
				break;
			case 's':
				/* source address list, separated by colon */
				status = parse_sourceaddr_list(&options->srcaddr_list, optarg);
				if (1 == status)
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_SRCNOIP;
					return 1;
				}
				else if (2 == status)
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_SRCNOUC;
					return 1;
				}
				break;
			case 't':
				/* query timeout, in 100ms units */
				errno = 0;
				tmp = strtoul(optarg, &endptr, 10);
				if (errno != 0)
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVTIMEOUT;
					return 1;
				}
				options->query_timeout = tmp;
				timeout_set = 1;
				break;
			case 'v':
				/* print version */
				options->opt_result = OPT_VERSION;
				return 0;
				break;
			case 'V':
				/* IGMP query version */
				if (0 == strcmp(optarg, "1"))
				{
					options->query_version = IGMP_V1;
				}
				else if (0 == strcmp(optarg, "2"))
				{
					options->query_version = IGMP_V2;
				}
				else if (0 == strcmp(optarg, "3"))
				{
					options->query_version = IGMP_V3;
				}
				else
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_IGMPVER;
					return 1;
				}
				break;
			case ':':
				/* argument for parameter missing */
				options->opt_result = OPT_ERROR;
				*errstring = OPTPARSE_ERROR_ARGMISSING;
				return 1;
				break;
			case '?':
			default:
				/* unknown parameter */
				options->opt_result = OPT_ERROR;
				*errstring = OPTPARSE_ERROR_UNKNOWN;
				return 1;
				break;
		}
	}

	if (! listen_mode)
	{
		/* check timeout/maxresp values per version */

		if (options->query_timeout > 31744U)
		{
			options->opt_result = OPT_ERROR;
			*errstring = OPTPARSE_ERROR_INVTIMEOUT;
			return 1;
		}

		switch(options->query_version)
		{
			case IGMP_V2:
				if ((0U == options->query_max_resp) || (options->query_max_resp > 255U))
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVMAXRESPV2;
					return 1;
				}

				if ((! maxresp_set) && (timeout_set))
				{
					/* set max resp time to timeout, clamped to max value of 255 */
					if (options->query_timeout > 255U)
					{
						options->query_max_resp = 255U;
					}
					else if (0U == options->query_timeout)
					{
						options->query_max_resp = DEFAULT_MAXRESP;
					}
					else
					{
						options->query_max_resp = options->query_timeout;
					}
				}
				break;
			case IGMP_V3:
				if ((0U == options->query_max_resp) || (options->query_max_resp > 31744U))
				{
					options->opt_result = OPT_ERROR;
					*errstring = OPTPARSE_ERROR_INVMAXRESPV3;
					return 1;
				}

				if ((! maxresp_set) && (timeout_set))
				{
					/* set max resp time to timeout, clamped to max value of 31744 */
					if (options->query_timeout > 31744U)
					{
						options->query_max_resp = 31744U;
					}
					else if (0U == options->query_timeout)
					{
						options->query_max_resp = DEFAULT_MAXRESP;
					}
					else
					{
						options->query_max_resp = options->query_timeout;
					}
				}
				break;
			default:
				break;
		}
	}

	if ((argc - optind) > 1)
	{
		/* too many args */
		options->opt_result = OPT_ERROR;
		*errstring = OPTPARSE_ERROR_TOOMANYARGS;
		return 1;
	}
	else if (1 == (argc - optind))
	{
		/* group specific query */
		status = string_to_ip_address(&options->query_address, argv[optind]);
		if (-1 == status)
		{
			options->opt_result = OPT_ERROR;
			*errstring = OPTPARSE_ERROR_ARGNOIP;
			return 1;
		}
		else if (! is_multicast_ip_address(&options->query_address))
		{
			options->opt_result = OPT_ERROR;
			*errstring = OPTPARSE_ERROR_ARGNOMC;
			return 1;
		}
		options->opt_result = OPT_GROUPSPEC;
	}
	else
	{
		/* general query */
		options->opt_result = OPT_GENERAL;
	}

	if (listen_mode)
	{
		options->opt_result = OPT_LISTEN;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int status = 0;
	struct parsed_options opts;
	const char *error_string = "";
	int send_sockd = -1;
	int rec_sockd = -1;
	struct igmp_send_options sendopts = IGMP_SEND_OPTIONS_INIT;
	const struct source_address_list *srcaddrlist = NULL;
	struct timespec query_timeout;

	/* parse commandline options */
	init_options(&opts);

	if(parse_options(&opts, argc, argv, &error_string) != 0)
	{
		printf("Error: %s\n", error_string);
		return ECODE_OPTERROR;
	}

	/* execute desired mode */
	switch(opts.opt_result)
	{
		case OPT_HELP:
			printf(HELP_TEXT);
			return 0;
			break;
		case OPT_VERSION:
			printf(VERSION_TEXT);
			return 0;
			break;
		case OPT_GROUPSPEC:
		case OPT_GENERAL:
			/* set up sockets */
			if (open_send_socket(&send_sockd, opts.query_version, &error_string) != 0)
			{
				printf("Error opening send socket: %s\n", error_string);
				return ECODE_ERROR;
			}

			if (open_receive_socket(&rec_sockd, &error_string) != 0)
			{
				printf("Error opening receive socket: %s\n", error_string);
				return ECODE_ERROR;
			}

			/* send query */
			sendopts.version = opts.query_version;
			sendopts.response_time = opts.query_max_resp;
			sendopts.set_s_flag = opts.query_set_flag;
			sendopts.qrv_value = opts.query_qrv_value;
			sendopts.qqic_value = opts.query_qqic_value;

			if (opts.query_timeout != 0U)
			{
				query_timeout.tv_nsec = (opts.query_timeout % 10) * 100000000U;
				query_timeout.tv_sec = (opts.query_timeout / 10);
			}

			switch (opts.query_version)
			{
				case IGMP_V1:
					if (opts.query_timeout != 0U)
					{
						printf("Sending IGMPv1 Query, waiting for reports (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);
					}
					else
					{
						printf("Sending IGMPv1 Query, waiting for reports (no timeout)...\n\n");
					}
					status = send_igmp_query(send_sockd, NULL, &sendopts, NULL);
					break;
				case IGMP_V2:
					if (OPT_GENERAL == opts.opt_result)
					{
						if (opts.query_timeout != 0U)
						{
							printf("Sending IGMPv2 Query (general), waiting for reports (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);
						}
						else
						{
							printf("Sending IGMPv2 Query (general), waiting for reports (no timeout)...\n\n");
						}
						status = send_igmp_query(send_sockd, NULL, &sendopts, NULL);
					}
					else
					{
						if (opts.query_timeout != 0U)
						{
							printf("Sending IGMPv2 Query (group-specific, for ");
							print_ipv4_address(&opts.query_address);
							printf("), waiting for reports (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);
						}
						else
						{
							printf("Sending IGMPv2 Query (group-specific, for ");
							print_ipv4_address(&opts.query_address);
							printf("), waiting for reports (no timeout)...\n\n");
						}
						status = send_igmp_query(send_sockd, &opts.query_address, &sendopts, NULL);
					}
					break;
				case IGMP_V3:
					if (source_address_list_get_length(&opts.srcaddr_list) > 0U)
					{
						srcaddrlist = &opts.srcaddr_list;
					}

					if (OPT_GENERAL == opts.opt_result)
					{
						if (opts.query_timeout != 0U)
						{
							printf("Sending IGMPv3 Query (general), waiting for reports (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);
						}
						else
						{
							printf("Sending IGMPv3 Query (general), waiting for reports (no timeout)...\n\n");
						}
						status = send_igmp_query(send_sockd, NULL, &sendopts, NULL);
					}
					else
					{
						if (opts.query_timeout != 0U)
						{
							printf("Sending IGMPv3 Query (group-specific, for ");
							print_ipv4_address(&opts.query_address);
							printf("), waiting for reports (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);
						}
						else
						{
							printf("Sending IGMPv3 Query (group-specific, for ");
							print_ipv4_address(&opts.query_address);
							printf("), waiting for reports (no timeout)...\n\n");
						}
						status = send_igmp_query(send_sockd, &opts.query_address, &sendopts, srcaddrlist);
					}
					break;
				default:
					break;
			}

			if (status != 0)
			{
				printf("Error while sending IGMP query\n");
				return ECODE_ERROR;
			}

			/* wait for reports */
			if (opts.query_timeout != 0U)
			{
				status = receive_igmp_messages(rec_sockd, &query_timeout);
			}
			else
			{
				status = receive_igmp_messages(rec_sockd, NULL);
			}

			if (-1 == status)
			{
				printf("Error while receiving IGMP reports\n");
				return ECODE_ERROR;
			}
			else if (1 == status)
			{
				return ECODE_NOREPORT;
			}

			break;
		case OPT_LISTEN:
			/* wait for reports, withput sending query */

			if (open_receive_socket(&rec_sockd, &error_string) != 0)
			{
				printf("Error opening receive socket: %s\n", error_string);
				return ECODE_ERROR;
			}

			if (opts.query_timeout != 0U)
			{
				query_timeout.tv_nsec = (opts.query_timeout % 10) * 100000000U;
				query_timeout.tv_sec = (opts.query_timeout / 10);

				printf("Waiting for IGMP messages (timeout: %lds, %ldns)...\n\n", query_timeout.tv_sec, query_timeout.tv_nsec);

				status = receive_igmp_messages(rec_sockd, &query_timeout);
			}
			else
			{
				printf("Waiting for IGMP messages (no timeout)...\n\n");

				status = receive_igmp_messages(rec_sockd, NULL);
			}

			if (-1 == status)
			{
				printf("Error while receiving IGMP reports\n");
				return ECODE_ERROR;
			}
			else if (1 == status)
			{
				return ECODE_NOREPORT;
			}
			break;
		default:
			printf("Error: unknown mode\n");
			return -1;
	}

	return ECODE_OK;
}

