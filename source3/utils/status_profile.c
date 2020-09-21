/*
 * Unix SMB/CIFS implementation.
 * status reporting
 * Copyright (C) Andrew Tridgell 1994-1998
 * Copyright (C) James Peach 2005-2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbprofile.h"
#include "status_profile.h"
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"

static bool first_done;
static bool header_complete;

static void profile_separator(const char * title, struct json_object jsobj,
			      struct json_object *jo, enum PROFILE_OUTPUT proft)
{
	int ret;
	size_t tlen;
	char l[80] = {0};
	char * end;
	switch (proft) {
	case PROF_TEXT:
		snprintf(l, sizeof(l), "**** %s ", title);

		for (end = l + strlen(l); end < &l[sizeof(l) -1]; ++end) {
			*end = '*';
		}

		l[sizeof(l) - 1] = '\0';
		d_printf("%s\n", l);
		break;
	case PROF_JSON:
		tlen = strlen(title);
		SMB_ASSERT(tlen < 80);
		memcpy(l, title + 1, (tlen -2));

		*jo = json_new_object();
		if (json_is_invalid(jo)) {
			fprintf(stderr, "jo is invalid JSON\n");
			return;
		}
		ret = json_add_object(&jsobj, l, jo);
		if (ret != 0) {
			fprintf(stderr, "failed to add new json object: %s\n",
				title);
		}
		break;
	case PROF_CSV:
		break;
	}
	return;
}

/*******************************************************************
 dump the elements of the profile structure
  ******************************************************************/
bool status_profile_dump(bool verbose,  enum PROFILE_OUTPUT proft)
{
	TALLOC_CTX *mem_ctx = NULL;
	int ret;
	struct profile_stats stats = {};
	struct json_object jo, jsobj;
	bool json, csv;
	char fname[80] = {0};
	char elem[3] = {0};
	char csvout[1024] = {0};
	struct timeval tv;

	if (!profile_setup(NULL, True)) {
		fprintf(stderr,"Failed to initialise profile memory\n");
		return False;
	}
	if (proft == PROF_JSON) {
		mem_ctx = talloc_new(NULL);
		if (mem_ctx == NULL) {
			fprintf(stderr, "talloc_new() failed\n");
			return False;
		}
		jsobj = json_new_object();
		if (json_is_invalid(&jsobj)) {
			fprintf(stderr, "jsobj is invalid\n");
			return False;
		}
		ret = json_add_timestamp(&jsobj);
		if (ret < 0) {
			fprintf(stderr, "Failed to add timestamp to JSON.\n");
			json_free(&jsobj);
			return False;
		}
	}

	smbprofile_collect(&stats);

#define __PRINT_FIELD_LINE(name, _stats, field) do { \
	uintmax_t val = (uintmax_t)stats.values._stats.field; \
	if (proft == PROF_JSON) { \
		snprintf(fname, sizeof(fname), "%s_%s", name, #field); \
		if (json_add_int(&jo, fname, val) < 0) { \
			json_free(&jsobj); \
			return False; \
		} \
	} \
	else if (proft == PROF_CSV) { \
		if (!header_complete) { \
			if (!first_done) { \
				printf("timestamp"); \
				gettimeofday(&tv, NULL); \
				snprintf(csvout, sizeof(csvout), "%ld", tv.tv_sec); \
			} \
			printf(",%s_%s", name, #field); \
			snprintf(elem, sizeof(elem), ",%lu", val); \
		} \
		else { \
			if (!first_done) { \
				gettimeofday(&tv, NULL); \
				snprintf(csvout, sizeof(csvout), "%ld", tv.tv_sec); \
			} \
			snprintf(elem, sizeof(elem), ",%lu", val); \
		} \
		first_done = True; \
		strncat(csvout, elem, sizeof(csvout) - strlen(csvout) - 1); \
	} \
	else {\
		d_printf("%-59s%20ju\n", \
			 name "_" #field ":", \
			 val); \
	}\
} while(0);
#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display) profile_separator(#display, jsobj, &jo, proft);
#define SMBPROFILE_STATS_COUNT(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
} while(0);
#define SMBPROFILE_STATS_TIME(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
} while(0);
#define SMBPROFILE_STATS_BASIC(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
} while(0);
#define SMBPROFILE_STATS_BYTES(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
	__PRINT_FIELD_LINE(#name, name##_stats,  idle); \
	__PRINT_FIELD_LINE(#name, name##_stats,  bytes); \
} while(0);
#define SMBPROFILE_STATS_IOBYTES(name) do { \
	__PRINT_FIELD_LINE(#name, name##_stats,  count); \
	__PRINT_FIELD_LINE(#name, name##_stats,  time); \
	__PRINT_FIELD_LINE(#name, name##_stats,  idle); \
	__PRINT_FIELD_LINE(#name, name##_stats,  inbytes); \
	__PRINT_FIELD_LINE(#name, name##_stats,  outbytes); \
} while(0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef __PRINT_FIELD_LINE
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

	first_done = False;
	if (proft == PROF_JSON) {
		printf("%s\n", json_to_string(mem_ctx, &jsobj));
		TALLOC_FREE(mem_ctx);
		json_free(&jsobj);
	}
	else if (proft == PROF_CSV) {
		if (!header_complete) {
			printf("\n");
		}
		printf("%s\n", csvout);
	}
	header_complete = True;
	return True;
}

/* Convert microseconds to milliseconds. */
#define usec_to_msec(s) ((s) / 1000)
/* Convert microseconds to seconds. */
#define usec_to_sec(s) ((s) / 1000000)
/* One second in microseconds. */
#define one_second_usec (1000000)

#define sample_interval_usec one_second_usec

#define percent_time(used, period) ((double)(used) / (double)(period) * 100.0 )

static uint64_t print_count_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_count * const current,
	const struct smbprofile_stats_count * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%-40s %ju/sec",
				name, (uintmax_t)(step / delta_sec));
		} else {
			printf("%-40s %s %ju/sec\n",
				buf, name, (uintmax_t)(step / delta_sec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_basic_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_basic * const current,
	const struct smbprofile_stats_basic * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_bytes_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_bytes * const current,
	const struct smbprofile_stats_bytes * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_iobytes_count_samples(
	char *buf, const size_t buflen,
	const char *name,
	const struct smbprofile_stats_iobytes * const current,
	const struct smbprofile_stats_iobytes * const last,
	uint64_t delta_usec)
{
	uint64_t step = current->count - last->count;
	uint64_t spent = current->time - last->time;
	uint64_t count = 0;

	if (step != 0) {
		uint64_t delta_sec = usec_to_sec(delta_usec);

		count++;

		if (buf[0] == '\0') {
			snprintf(buf, buflen,
				"%s %ju/sec (%.2f%%)",
				name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
		} else {
			printf("%-40s %s %ju/sec (%.2f%%)\n",
				buf, name, (uintmax_t)(step / delta_sec),
				percent_time(spent, delta_usec));
			buf[0] = '\0';
		}
	}

	return count;
}

static uint64_t print_count_samples(
	const struct profile_stats * const current,
	const struct profile_stats * const last,
	uint64_t delta_usec)
{
	uint64_t count = 0;
	char buf[60] = { '\0', };

	if (delta_usec == 0) {
		return 0;
	}

#define SMBPROFILE_STATS_START
#define SMBPROFILE_STATS_SECTION_START(name, display)
#define SMBPROFILE_STATS_COUNT(name) do { \
	count += print_count_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_TIME(name) do { \
} while(0);
#define SMBPROFILE_STATS_BASIC(name) do { \
	count += print_basic_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_BYTES(name) do { \
	count += print_bytes_count_samples(buf, sizeof(buf), \
					   #name, \
					   &current->values.name##_stats, \
					   &last->values.name##_stats, \
					   delta_usec); \
} while(0);
#define SMBPROFILE_STATS_IOBYTES(name) do { \
	count += print_iobytes_count_samples(buf, sizeof(buf), \
					     #name, \
					     &current->values.name##_stats, \
					     &last->values.name##_stats, \
					     delta_usec); \
} while(0);
#define SMBPROFILE_STATS_SECTION_END
#define SMBPROFILE_STATS_END
	SMBPROFILE_STATS_ALL_SECTIONS
#undef SMBPROFILE_STATS_START
#undef SMBPROFILE_STATS_SECTION_START
#undef SMBPROFILE_STATS_COUNT
#undef SMBPROFILE_STATS_TIME
#undef SMBPROFILE_STATS_BASIC
#undef SMBPROFILE_STATS_BYTES
#undef SMBPROFILE_STATS_IOBYTES
#undef SMBPROFILE_STATS_SECTION_END
#undef SMBPROFILE_STATS_END

	if (buf[0] != '\0') {
		printf("%-40s\n", buf);
		buf[0] = '\0';
	}

	return count;
}

static struct profile_stats	sample_data[2];
static uint64_t		sample_time[2];

bool status_profile_rates(bool verbose)
{
	uint64_t remain_usec;
	uint64_t next_usec;
	uint64_t delta_usec;

	int last = 0;
	int current = 1;
	int tmp;

	if (verbose) {
	    fprintf(stderr, "Sampling stats at %d sec intervals\n",
		    usec_to_sec(sample_interval_usec));
	}

	if (!profile_setup(NULL, True)) {
		fprintf(stderr,"Failed to initialise profile memory\n");
		return False;
	}

	smbprofile_collect(&sample_data[last]);
	for (;;) {
		sample_time[current] = profile_timestamp();
		next_usec = sample_time[current] + sample_interval_usec;

		/* Take a sample. */
		smbprofile_collect(&sample_data[current]);

		/* Rate convert some values and print results. */
		delta_usec = sample_time[current] - sample_time[last];

		if (print_count_samples(&sample_data[current],
			&sample_data[last], delta_usec)) {
			printf("\n");
		}

		/* Swap sampling buffers. */
		tmp = last;
		last = current;
		current = tmp;

		/* Delay until next sample time. */
		remain_usec = next_usec - profile_timestamp();
		if (remain_usec > sample_interval_usec) {
			fprintf(stderr, "eek! falling behind sampling rate!\n");
		} else {
			if (verbose) {
			    fprintf(stderr,
				    "delaying for %lu msec\n",
				    (unsigned long )usec_to_msec(remain_usec));
			}

			usleep(remain_usec);
		}

	}

	return True;
}

bool status_profile_timed_dump(bool verbose, enum PROFILE_OUTPUT proft, uint64_t sample_interval)
{
	uint64_t remain_usec;
	uint64_t next_usec;
	uint64_t delta_usec;
	uint64_t interval;
	bool ret;
	int last = 0;
	int current = 1;
	int tmp;
	interval = sample_interval * one_second_usec;

	for (;/*ever*/;) {
		sample_time[current] = profile_timestamp();
		next_usec = sample_time[current] + interval;
		ret = status_profile_dump(verbose, proft);
		if (!ret) {
			fprintf(stderr, "Timed dump failed\n");
			return False;
		}
		last = current;
		current = tmp;
		ret = fflush(stdout);
		if (ret != 0) {
			fprintf(stderr, "Failed to flush output stream: %s\n",
				strerror(errno));
			return False;
		}
		remain_usec = next_usec - profile_timestamp();
		if (remain_usec > interval) {
			fprintf(stderr, "eek! falling behind sampling rate!\n");
		} else {
			usleep(remain_usec);
		}
	}
	return True;
}
