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

#ifndef IGMP_TESTER_H_
#define IGMP_TESTER_H_

#define _POSIX_C_SOURCE 200112L

#include <unistd.h>

#include "igmping_common.h"
#include "igmping_socket.h"
#include "igmping_v3.h"
#include "igmping_v2.h"
#include "igmping_v1.h"

#define HELP_TEXT "igmping [OPTIONS] [multicast address to query OR empty for general query]\n" \
					"OPTIONS:\n" \
					"\t-h\t\tprint help\n" \
					"\t-v\t\tprint version\n" \
					"\t-l\t\tstart in listen mode\n" \
					"\t-V <version>\tIGMP version of query (1, 2 or 3)\n" \
					"\t-t <timeout>\tquery/listen timeout in units of 100ms, or 0 for no timeout (0-31744)\n" \
					"\t-m <max resp time/code>\tset Max Resp Time/Code in query (v2: 1-255, v3: 1-31744)\n" \
					"\t-s <srcaddr1,srcaddr2,..,srcaddrN>\tcomma-separated list of unicast source addresses (v3 only)\n" \
					"\t-f\t\tset S flag in query (v3 only)\n" \
					"\t-q <QRV value>\tset QRV value in query (v3 only, 0-7)\n" \
					"\t-r <QQIC value>\tset QQIC value in query (v3 only, 0-31744)\n" \
					"\n"

#define VERSION_TEXT "igmping 1.0\n\n"

#define ECODE_ERROR -1		/* exit code for general error (e. g. socket error) */
#define ECODE_OK 0			/* exit code for success */
#define ECODE_OPTERROR 1	/* exit code for error while processing options */
#define ECODE_NOREPORT 2	/* exit code for no report received until timeout */


#define OPTPARSE_ERROR_UNKNOWN "unknown option"
#define OPTPARSE_ERROR_ARGMISSING "missing argument for option"
#define OPTPARSE_ERROR_TOOMANYARGS "too many arguments"
#define OPTPARSE_ERROR_ARGNOIP "argument is not a valid IP address"
#define OPTPARSE_ERROR_ARGNOMC "argument is not a valid multicast address"
#define OPTPARSE_ERROR_IGMPVER "invalid IGMP version (must be 1, 2 or 3)"
#define OPTPARSE_ERROR_INVTIMEOUT "invalid timeout value (must be between 0 and 31744)"
#define OPTPARSE_ERROR_INVMAXRESP "invalid max response time/code"
#define OPTPARSE_ERROR_INVMAXRESPV2 "invalid max response time value (must be between 1 and 255)"
#define OPTPARSE_ERROR_INVMAXRESPV3 "invalid max response code value (must be between 1 and 31744)"
#define OPTPARSE_ERROR_INVQRV "invalid QRV value (must be between 0 and 7)"
#define OPTPARSE_ERROR_INVQQIC "invalid QQIC value (must be between 0 and 31744)"
#define OPTPARSE_ERROR_SRCNOIP "source address list contains string which is not a valid IP address"
#define OPTPARSE_ERROR_SRCNOUC "source address list contains string which is not a valid unicast address"

enum option_result { 	OPT_ERROR = 0,	/* option parse error */
						OPT_HELP,		/* print help */
						OPT_VERSION,	/* print version */
						OPT_GENERAL,	/* normal mode, send general query and wait for reports */
						OPT_GROUPSPEC,	/* normal mode, send grop-specific query and wait for response */
						OPT_LISTEN		/* passive mode, only listen for reports */
};

struct igmp_send_options
{
	enum igmp_version version;
	unsigned int response_time;	/* v3: 1 - 31744, v2: 1 - 255 */
	enum boolean_flag set_s_flag;
	unsigned char qrv_value;		/* 0 - 7 */
	unsigned int qqic_value;		/* 0 - 31744 */
};
#define IGMP_SEND_OPTIONS_INIT {IGMP_V2, 100U, FALSE, 0U, 0U}

struct igmp_receive_vector
{
	struct ip_receive_info ip_info;
	enum igmp_message_type message_type;
	struct igmp_report_v1 report_v1;
	struct igmp_report_v2 report_v2;
	struct igmp_leave_group_v2 leave_group_v2;
	struct igmp_report_v3 report_v3;
};

struct parsed_options
{
	enum option_result opt_result;
	enum igmp_version query_version;
	struct ipv4_address query_address;
	unsigned int query_timeout;	/* in multiples of 100ms */
	unsigned int query_max_resp;	/* in multiples of 100ms */
	struct source_address_list srcaddr_list;
	enum boolean_flag query_set_flag;
	unsigned char query_qrv_value;
	unsigned int query_qqic_value;
};

int send_igmp_query(int socket_desc, const struct ipv4_address *group_address, const struct igmp_send_options *send_options, const struct source_address_list *src_addr_list);

void init_receive_vector(struct igmp_receive_vector *receive_vector);
void free_receive_vector(struct igmp_receive_vector *receive_vector);
int process_igmp_message(struct igmp_receive_vector *receive_vector, const unsigned char raw_message[], size_t raw_message_len, const char **error_string);
int receive_igmp_report(int socket_desc, struct igmp_receive_vector *receive_vector, const struct timespec *timeout, const char **error_string);
void print_group_record_info(const struct igmp_group_record_v3 *group_record);
void print_report_info(const struct igmp_receive_vector *receive_vector);
int receive_igmp_messages(int socket_desc, const struct timespec *timeout);

void init_options(struct parsed_options *options);
int parse_sourceaddr_list(struct source_address_list *srclist, const char string[]);
int parse_options(struct parsed_options *options, int argc, char *argv[], const char **errstring);

#endif /* IGMP_TESTER_H_ */
