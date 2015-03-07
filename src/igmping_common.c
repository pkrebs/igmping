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

#define _POSIX_C_SOURCE 200112L

#include "igmping_common.h"

/* returns:
 * timespec deadline as sum of current time and waittime */
void get_deadline(struct timespec *deadline, const struct timespec *waittime)
{
	struct timespec now;

	assert(deadline != NULL);
	assert(waittime != NULL);

	assert(waittime->tv_sec >= 0);
	assert((waittime->tv_nsec >= 0) && (waittime->tv_nsec <= 999999999));

	assert(0 == clock_gettime(CLOCK_REALTIME, &now));

	/* add waittime to now, taking care of nsec to sec oveflow */
	deadline->tv_nsec = now.tv_nsec + waittime->tv_nsec;

	deadline->tv_sec = now.tv_sec + waittime->tv_sec + (deadline->tv_nsec / 1000000000);
	deadline->tv_nsec = deadline->tv_nsec % 1000000000;
}

/*
 * returns:
 * 0 ... current time earlier than deadline
 * 1 ... current time equal or later than deadline
 */
int get_remaining_time(struct timespec *remaining_time, const struct timespec *deadline)
{
	struct timespec now;

	assert(remaining_time != NULL);
	assert(deadline != NULL);

	assert(deadline->tv_sec >= 0);
	assert((deadline->tv_nsec >= 0) && (deadline->tv_nsec <= 999999999));

	memset(remaining_time, 0, sizeof(struct timespec));

	assert(0 == clock_gettime(CLOCK_REALTIME, &now));

	/* get time difference between now and deadline */
	if (now.tv_sec > deadline->tv_sec)
	{
		return 1;
	}
	else if (now.tv_sec == deadline->tv_sec)
	{
		if (now.tv_nsec >= deadline->tv_nsec)
		{
			return 1;
		}
		else
		{
			remaining_time->tv_nsec = deadline->tv_nsec - now.tv_nsec;
		}
	}
	else
	{
		remaining_time->tv_sec = (deadline->tv_sec - now.tv_sec) - 1;

		if(now.tv_nsec == deadline->tv_nsec)
		{
			remaining_time->tv_sec++;
		}
		else if(deadline->tv_nsec < now.tv_nsec)
		{
			remaining_time->tv_nsec = 1000000000 - (now.tv_nsec - deadline->tv_nsec);
		}
		else
		{
			remaining_time->tv_sec++;
			remaining_time->tv_nsec = deadline->tv_nsec - now.tv_nsec;
		}
	}

	return 0;
}

/*
 * returns:
 * 0 ... address is not a unicast ip address
 * 1 ... address is a unicast ip address
 */
int is_unicast_ip_address(const struct ipv4_address *address)
{
	assert(address != NULL);

	return (address->octetts[0] < 224U);
}

/*
 * returns:
 * 0 ... address is not a multicast ip address
 * 1 ... address is a multicast ip address
 */
int is_multicast_ip_address(const struct ipv4_address *address)
{
	assert(address != NULL);

	return ((address->octetts[0] & 240U) == 224U);
}

void int_to_ipv4_address(struct ipv4_address *address, unsigned int address_int)
{
	assert(address != NULL);
	assert(address_int <= 4294967295U);

	address->octetts[0] = address_int >> 24U;
	address->octetts[1] = address_int >> 16U;
	address->octetts[2] = address_int >> 8U;
	address->octetts[3] = address_int;
}

static void octett_to_string(char string[], unsigned char octett)
{
	const char digits[11] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

	assert(string != NULL);

	memset(string, 0, 4U);

	if (octett >= 100U)
	{
		string[0] = digits[octett/100];
		string[1] = digits[(octett%100)/10];
		string[2] = digits[octett%10];
	}
	else if (octett >= 10)
	{
		string[0] = digits[octett/10];
		string[1] = digits[octett%10];
	}
	else
	{
		string[0] = digits[octett];
	}

}

void ip_address_to_string(char ip_string[], const struct ipv4_address *address)
{
	char octstr[4];

	assert(ip_string != NULL);
	assert(address != NULL);

	octett_to_string(octstr, address->octetts[0]);
	strcpy(ip_string, octstr);
	strcat(ip_string, ".");

	octett_to_string(octstr, address->octetts[1]);
	strcat(ip_string, octstr);
	strcat(ip_string, ".");

	octett_to_string(octstr, address->octetts[2]);
	strcat(ip_string, octstr);
	strcat(ip_string, ".");

	octett_to_string(octstr, address->octetts[3]);
	strcat(ip_string, octstr);
}

/*
 * returns:
 * -1 ... string not a valid octett for an IP address
 * 0 ... otherwise
 */
static int string_to_octett(unsigned char *octett, const char string[])
{
	size_t len = 0U;
	int tmp = 0;

	assert(octett != NULL);
	assert(string != NULL);

	len = strlen(string);

	if ((0U == len) || (len > 3U))
	{
		return -1;
	}

	tmp = atoi(string);
	if ((tmp < 0) || (tmp > 255))
	{
		return -1;
	}

	*octett = (unsigned char) tmp;

	return 0;
}

/*
 * returns:
 * -1 ... string not a valid IPv4 address
 * 0 ... otherwise
 */
int string_to_ip_address(struct ipv4_address *address, const char ip_string[])
{
	size_t i = 0U;
	size_t octnum = 0;
	size_t len = 0U;
	size_t octlen = 0U;
	char buf[4] = {'\0'};

	assert(address != NULL);
	assert(ip_string != NULL);

	memset(address, 0U, sizeof(struct ipv4_address));

	len = strlen(ip_string);
	if (0 == len)
	{
		return -1;
	}

	for (i = 0U; i <= len; i++)
	{
		if ((i == len) || ('.' == ip_string[i]))
		{
			if ((0U == octlen) || (octlen > 3U) || (octnum > 3U))
			{
				return -1;
			}

			if (string_to_octett(&address->octetts[octnum], buf) != 0)
			{
				return -1;
			}
			memset(buf, 0U, sizeof(buf));
			octnum++;
			octlen = 0U;
		}
		else if (octlen >= 3U)
		{
			return -1;
		}
		else
		{
			buf[octlen] = ip_string[i];
			octlen++;
		}
	}

	return 0;
}

void print_ipv4_address(const struct ipv4_address *address)
{
	assert(address != NULL);

	printf("%u.%u.%u.%u", address->octetts[0], address->octetts[1], address->octetts[2], address->octetts[3]);
}

void calculate_checksum(unsigned char *checksum_high_byte, unsigned char *checksum_low_byte, const unsigned char *msg_raw, size_t msg_len)
{
	unsigned long checksum = 0U;
	unsigned int tmp = 0U;
	size_t i = 0U;

	assert(msg_raw != NULL);
	assert(!(msg_len & 1));

	/* sum all 16 bit words */
	for(i = 0U; i < msg_len; i = i + 2U)
	{
		tmp = msg_raw[i] << 8U;
		tmp = tmp | msg_raw[i + 1U];

		checksum = checksum + tmp;
	}

	/* when result is greater than 16 bit, add carry to lower 16 bit */
	if (checksum >> 16)
	{
		checksum = (checksum & 0xffff) + (checksum >> 16U);
	}

	/* take inverse */
	checksum = ~checksum;

	*checksum_high_byte = checksum >> 8U;
	*checksum_low_byte = checksum;
}

/*
 * returns:
 * -1 ... checksum invalid
 * 0 ... checksum valid
 */
int verify_checksum(const unsigned char raw_message[], size_t raw_message_len)
{
	int status = 0;
	unsigned char high_byte = 255U;
	unsigned char low_byte = 255U;

	assert(raw_message != NULL);

	calculate_checksum(&high_byte, &low_byte, raw_message, raw_message_len);

	if ((high_byte != 0U) || (low_byte != 0))
	{
		status = -1;
	}

	return status;
}
