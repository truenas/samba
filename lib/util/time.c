/*
   Unix SMB/CIFS implementation.
   time handling functions

   Copyright (C) Andrew Tridgell 		1992-2004
   Copyright (C) Stefan (metze) Metzmacher	2002
   Copyright (C) Jeremy Allison			2007
   Copyright (C) Andrew Bartlett                2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/time.h"
#include "byteorder.h"
#include "time_basic.h"
#include "lib/util/time.h" /* Avoid /usr/include/time.h */
#include <sys/stat.h>
#ifndef NO_CONFIG_H
#include "config.h"
#endif

/**
 * @file
 * @brief time handling functions
 */

#if (SIZEOF_LONG == 8)
#define TIME_FIXUP_CONSTANT_INT 11644473600L
#elif (SIZEOF_LONG_LONG == 8)
#define TIME_FIXUP_CONSTANT_INT 11644473600LL
#endif


#define NSEC_PER_SEC 1000000000

/**
 External access to time_t_min and time_t_max.
**/
_PUBLIC_ time_t get_time_t_max(void)
{
	return TIME_T_MAX;
}

/**
a wrapper to preferably get the monotonic time
**/
_PUBLIC_ void clock_gettime_mono(struct timespec *tp)
{
/* prefer a suspend aware monotonic CLOCK_BOOTTIME: */
#ifdef CLOCK_BOOTTIME
	if (clock_gettime(CLOCK_BOOTTIME,tp) == 0) {
		return;
	}
#endif
/* then try the  monotonic clock: */
#ifndef CUSTOM_CLOCK_MONOTONIC_IS_REALTIME
	if (clock_gettime(CUSTOM_CLOCK_MONOTONIC,tp) == 0) {
		return;
	}
#endif
	clock_gettime(CLOCK_REALTIME,tp);
}

/**
a wrapper to preferably get the monotonic time in seconds
**/
_PUBLIC_ time_t time_mono(time_t *t)
{
	struct timespec tp;

	clock_gettime_mono(&tp);
	if (t != NULL) {
		*t = tp.tv_sec;
	}
	return tp.tv_sec;
}


#define TIME_FIXUP_CONSTANT 11644473600LL

time_t convert_timespec_to_time_t(struct timespec ts)
{
	/* Ensure tv_nsec is less than 1sec. */
	normalize_timespec(&ts);

	/* 1 ns == 1,000,000,000 - one thousand millionths of a second.
	   increment if it's greater than 500 millionth of a second. */

	if (ts.tv_nsec > 500000000) {
		return ts.tv_sec + 1;
	}
	return ts.tv_sec;
}

struct timespec convert_time_t_to_timespec(time_t t)
{
	struct timespec ts;
	ts.tv_sec = t;
	ts.tv_nsec = 0;
	return ts;
}



/**
 Interpret an 8 byte "filetime" structure to a time_t
 It's originally in "100ns units since jan 1st 1601"

 An 8 byte value of 0xffffffffffffffff will be returned as a timespec of

	tv_sec = 0
	tv_nsec = 0;

 Returns GMT.
**/
time_t nt_time_to_unix(NTTIME nt)
{
	return convert_timespec_to_time_t(nt_time_to_unix_timespec(nt));
}


/**
put a 8 byte filetime from a time_t
This takes GMT as input
**/
_PUBLIC_ void unix_to_nt_time(NTTIME *nt, time_t t)
{
	uint64_t t2;

	if (t == (time_t)-1) {
		*nt = (NTTIME)-1LL;
		return;
	}

	if (t == TIME_T_MAX || t == INT64_MAX) {
		*nt = 0x7fffffffffffffffLL;
		return;
	}

	if (t == 0) {
		*nt = 0;
		return;
	}

	t2 = t;
	t2 += TIME_FIXUP_CONSTANT_INT;
	t2 *= 1000*1000*10;

	*nt = t2;
}


/**
check if it's a null unix time
**/
_PUBLIC_ bool null_time(time_t t)
{
	return t == 0 ||
		t == (time_t)0xFFFFFFFF ||
		t == (time_t)-1;
}


/**
check if it's a null NTTIME
**/
_PUBLIC_ bool null_nttime(NTTIME t)
{
	return t == 0;
}

/*******************************************************************
  create a 16 bit dos packed date
********************************************************************/
static uint16_t make_dos_date1(struct tm *t)
{
	uint16_t ret=0;
	ret = (((unsigned int)(t->tm_mon+1)) >> 3) | ((t->tm_year-80) << 1);
	ret = ((ret&0xFF)<<8) | (t->tm_mday | (((t->tm_mon+1) & 0x7) << 5));
	return ret;
}

/*******************************************************************
  create a 16 bit dos packed time
********************************************************************/
static uint16_t make_dos_time1(struct tm *t)
{
	uint16_t ret=0;
	ret = ((((unsigned int)t->tm_min >> 3)&0x7) | (((unsigned int)t->tm_hour) << 3));
	ret = ((ret&0xFF)<<8) | ((t->tm_sec/2) | ((t->tm_min & 0x7) << 5));
	return ret;
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
  This takes a GMT time and returns a packed localtime structure
********************************************************************/
static uint32_t make_dos_date(time_t unixdate, int zone_offset)
{
	struct tm *t;
	uint32_t ret=0;

	if (unixdate == 0) {
		return 0;
	}

	unixdate -= zone_offset;

	t = gmtime(&unixdate);
	if (!t) {
		return 0xFFFFFFFF;
	}

	ret = make_dos_date1(t);
	ret = ((ret&0xFFFF)<<16) | make_dos_time1(t);

	return ret;
}

/**
put a dos date into a buffer (time/date format)
This takes GMT time and puts local time in the buffer
**/
_PUBLIC_ void push_dos_date(uint8_t *buf, int offset, time_t unixdate, int zone_offset)
{
	uint32_t x = make_dos_date(unixdate, zone_offset);
	SIVAL(buf,offset,x);
}

/**
put a dos date into a buffer (date/time format)
This takes GMT time and puts local time in the buffer
**/
_PUBLIC_ void push_dos_date2(uint8_t *buf,int offset,time_t unixdate, int zone_offset)
{
	uint32_t x;
	x = make_dos_date(unixdate, zone_offset);
	x = ((x&0xFFFF)<<16) | ((x&0xFFFF0000)>>16);
	SIVAL(buf,offset,x);
}

/**
put a dos 32 bit "unix like" date into a buffer. This routine takes
GMT and converts it to LOCAL time before putting it (most SMBs assume
localtime for this sort of date)
**/
_PUBLIC_ void push_dos_date3(uint8_t *buf,int offset,time_t unixdate, int zone_offset)
{
	if (!null_time(unixdate)) {
		unixdate -= zone_offset;
	}
	SIVAL(buf,offset,unixdate);
}

/*******************************************************************
  interpret a 32 bit dos packed date/time to some parameters
********************************************************************/
void interpret_dos_date(uint32_t date,int *year,int *month,int *day,int *hour,int *minute,int *second)
{
	uint32_t p0,p1,p2,p3;

	p0=date&0xFF; p1=((date&0xFF00)>>8)&0xFF;
	p2=((date&0xFF0000)>>16)&0xFF; p3=((date&0xFF000000)>>24)&0xFF;

	*second = 2*(p0 & 0x1F);
	*minute = ((p0>>5)&0xFF) + ((p1&0x7)<<3);
	*hour = (p1>>3)&0xFF;
	*day = (p2&0x1F);
	*month = ((p2>>5)&0xFF) + ((p3&0x1)<<3) - 1;
	*year = ((p3>>1)&0xFF) + 80;
}

/**
  create a unix date (int GMT) from a dos date (which is actually in
  localtime)
**/
_PUBLIC_ time_t pull_dos_date(const uint8_t *date_ptr, int zone_offset)
{
	uint32_t dos_date=0;
	struct tm t;
	time_t ret;

	dos_date = IVAL(date_ptr,0);

	if (dos_date == 0) return (time_t)0;

	interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
			   &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
	t.tm_isdst = -1;

	ret = timegm(&t);

	ret += zone_offset;

	return ret;
}

/**
like make_unix_date() but the words are reversed
**/
_PUBLIC_ time_t pull_dos_date2(const uint8_t *date_ptr, int zone_offset)
{
	uint32_t x,x2;

	x = IVAL(date_ptr,0);
	x2 = ((x&0xFFFF)<<16) | ((x&0xFFFF0000)>>16);
	SIVAL(&x,0,x2);

	return pull_dos_date((const uint8_t *)&x, zone_offset);
}

/**
  create a unix GMT date from a dos date in 32 bit "unix like" format
  these generally arrive as localtimes, with corresponding DST
**/
_PUBLIC_ time_t pull_dos_date3(const uint8_t *date_ptr, int zone_offset)
{
	time_t t = (time_t)IVAL(date_ptr,0);

	if (t == (time_t)0xFFFFFFFF) {
		t = (time_t)-1;
	}

	if (!null_time(t)) {
		t += zone_offset;
	}
	return t;
}

/****************************************************************************
 Return the date and time as a string
****************************************************************************/

char *timeval_string(TALLOC_CTX *ctx, const struct timeval *tp, bool hires)
{
	struct timeval_buf tmp;
	char *result;

	result = talloc_strdup(ctx, timeval_str_buf(tp, false, hires, &tmp));
	if (result == NULL) {
		return NULL;
	}

	/*
	 * beautify the talloc_report output
	 *
	 * This is not just cosmetics. A C compiler might in theory make the
	 * talloc_strdup call above a tail call with the tail call
	 * optimization. This would render "tmp" invalid while talloc_strdup
	 * tries to duplicate it. The talloc_set_name_const call below puts
	 * the talloc_strdup call into non-tail position.
	 */
	talloc_set_name_const(result, result);
	return result;
}

/****************************************************************************
 Return the date and time as a string
****************************************************************************/

const char *timespec_string_buf(const struct timespec *tp,
				bool hires,
				struct timeval_buf *buf)
{
	time_t t;
	struct tm *tm = NULL;
	int len;

	if (is_omit_timespec(tp)) {
		strlcpy(buf->buf, "SAMBA_UTIME_OMIT", sizeof(buf->buf));
		return buf->buf;
	}

	t = (time_t)tp->tv_sec;
	tm = localtime(&t);

	if (tm == NULL) {
		if (hires) {
			len = snprintf(buf->buf, sizeof(buf->buf),
				       "%ld.%09ld seconds since the Epoch",
				       (long)tp->tv_sec, (long)tp->tv_nsec);
		} else {
			len = snprintf(buf->buf, sizeof(buf->buf),
				       "%ld seconds since the Epoch", (long)t);
		}
	} else if (!hires) {
		len = snprintf(buf->buf, sizeof(buf->buf),
			       "%04d-%02d-%02d %02d:%02d:%02d",
			       1900 + tm->tm_year,
			       tm->tm_mon + 1,
			       tm->tm_mday,
			       tm->tm_hour,
			       tm->tm_min,
			       tm->tm_sec);
	} else {
		len = snprintf(buf->buf, sizeof(buf->buf),
			       "%04d-%02d-%02d %02d:%02d:%02d.%09ld",
			       1900 + tm->tm_year,
			       tm->tm_mon + 1,
			       tm->tm_mday,
			       tm->tm_hour,
			       tm->tm_min,
			       tm->tm_sec,
			       (long)tp->tv_nsec);
	}
	if (len == -1) {
		return "";
	}

	return buf->buf;
}

char *current_timestring(TALLOC_CTX *ctx, bool hires)
{
	struct timeval tv;

	GetTimeOfDay(&tv);
	return timeval_string(ctx, &tv, hires);
}

/*
 * Return date and time as a minimal string avoiding funny characters
 * that may cause trouble in file names. We only use digits and
 * underscore ... or a minus/hyphen if we got negative time.
 */
char *minimal_timeval_string(TALLOC_CTX *ctx, const struct timeval *tp, bool hires)
{
	time_t t;
	struct tm *tm;

	t = (time_t)tp->tv_sec;
	tm = localtime(&t);
	if (!tm) {
		if (hires) {
			return talloc_asprintf(ctx, "%ld_%06ld",
					       (long)tp->tv_sec,
					       (long)tp->tv_usec);
		} else {
			return talloc_asprintf(ctx, "%ld", (long)t);
		}
	} else {
		if (hires) {
			return talloc_asprintf(ctx,
					       "%04d%02d%02d_%02d%02d%02d_%06ld",
					       tm->tm_year+1900,
					       tm->tm_mon+1,
					       tm->tm_mday,
					       tm->tm_hour,
					       tm->tm_min,
					       tm->tm_sec,
					       (long)tp->tv_usec);
		} else {
			return talloc_asprintf(ctx,
					       "%04d%02d%02d_%02d%02d%02d",
					       tm->tm_year+1900,
					       tm->tm_mon+1,
					       tm->tm_mday,
					       tm->tm_hour,
					       tm->tm_min,
					       tm->tm_sec);
		}
	}
}

char *current_minimal_timestring(TALLOC_CTX *ctx, bool hires)
{
	struct timeval tv;

	GetTimeOfDay(&tv);
	return minimal_timeval_string(ctx, &tv, hires);
}

/**
return a HTTP/1.0 time string
**/
_PUBLIC_ char *http_timestring(TALLOC_CTX *mem_ctx, time_t t)
{
	char *buf;
	char tempTime[60];
	struct tm *tm = localtime(&t);

	if (t == TIME_T_MAX) {
		return talloc_strdup(mem_ctx, "never");
	}

	if (!tm) {
		return talloc_asprintf(mem_ctx,"%ld seconds since the Epoch",(long)t);
	}

#ifndef HAVE_STRFTIME
	buf = talloc_strdup(mem_ctx, asctime(tm));
	if (buf[strlen(buf)-1] == '\n') {
		buf[strlen(buf)-1] = 0;
	}
#else
	strftime(tempTime, sizeof(tempTime)-1, "%a, %d %b %Y %H:%M:%S %Z", tm);
	buf = talloc_strdup(mem_ctx, tempTime);
#endif /* !HAVE_STRFTIME */

	return buf;
}

/**
 Return the date and time as a string
**/
_PUBLIC_ char *timestring(TALLOC_CTX *mem_ctx, time_t t)
{
	char *TimeBuf;
	char tempTime[80];
	struct tm *tm;

	tm = localtime(&t);
	if (!tm) {
		return talloc_asprintf(mem_ctx,
				       "%ld seconds since the Epoch",
				       (long)t);
	}

#ifdef HAVE_STRFTIME
	/* Some versions of gcc complain about using some special format
	 * specifiers. This is a bug in gcc, not a bug in this code. See a
	 * recent strftime() manual page for details. */
	strftime(tempTime,sizeof(tempTime)-1,"%a %b %e %X %Y %Z",tm);
	TimeBuf = talloc_strdup(mem_ctx, tempTime);
#else
	TimeBuf = talloc_strdup(mem_ctx, asctime(tm));
	if (TimeBuf == NULL) {
		return NULL;
	}
	if (TimeBuf[0] != '\0') {
		size_t len = strlen(TimeBuf);
		if (TimeBuf[len - 1] == '\n') {
			TimeBuf[len - 1] = '\0';
		}
	}
#endif

	return TimeBuf;
}

/**
  return a talloced string representing a NTTIME for human consumption
*/
_PUBLIC_ const char *nt_time_string(TALLOC_CTX *mem_ctx, NTTIME nt)
{
	time_t t;
	if (nt == 0) {
		return "NTTIME(0)";
	}
	t = nt_time_to_full_time_t(nt);
	return timestring(mem_ctx, t);
}


/**
  put a NTTIME into a packet
*/
_PUBLIC_ void push_nttime(uint8_t *base, uint16_t offset, NTTIME t)
{
	SBVAL(base, offset,   t);
}

/**
  pull a NTTIME from a packet
*/
_PUBLIC_ NTTIME pull_nttime(uint8_t *base, uint16_t offset)
{
	NTTIME ret = BVAL(base, offset);
	return ret;
}

/**
  return (tv1 - tv2) in microseconds
*/
_PUBLIC_ int64_t usec_time_diff(const struct timeval *tv1, const struct timeval *tv2)
{
	int64_t sec_diff = tv1->tv_sec - tv2->tv_sec;
	return (sec_diff * 1000000) + (int64_t)(tv1->tv_usec - tv2->tv_usec);
}

/**
  return (tp1 - tp2) in nanoseconds
*/
_PUBLIC_ int64_t nsec_time_diff(const struct timespec *tp1, const struct timespec *tp2)
{
	int64_t sec_diff = tp1->tv_sec - tp2->tv_sec;
	return (sec_diff * 1000000000) + (int64_t)(tp1->tv_nsec - tp2->tv_nsec);
}


/**
  return a zero timeval
*/
_PUBLIC_ struct timeval timeval_zero(void)
{
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	return tv;
}

/**
  return true if a timeval is zero
*/
_PUBLIC_ bool timeval_is_zero(const struct timeval *tv)
{
	return tv->tv_sec == 0 && tv->tv_usec == 0;
}

/**
  return a timeval for the current time
*/
_PUBLIC_ struct timeval timeval_current(void)
{
	struct timeval tv;
	GetTimeOfDay(&tv);
	return tv;
}

/**
  return a timeval struct with the given elements
*/
_PUBLIC_ struct timeval timeval_set(uint32_t secs, uint32_t usecs)
{
	struct timeval tv;
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	return tv;
}


/**
  return a timeval ofs microseconds after tv
*/
_PUBLIC_ struct timeval timeval_add(const struct timeval *tv,
			   uint32_t secs, uint32_t usecs)
{
	struct timeval tv2 = *tv;
	const unsigned int million = 1000000;
	tv2.tv_sec += secs;
	tv2.tv_usec += usecs;
	tv2.tv_sec += tv2.tv_usec / million;
	tv2.tv_usec = tv2.tv_usec % million;
	return tv2;
}

/**
  return the sum of two timeval structures
*/
struct timeval timeval_sum(const struct timeval *tv1,
			   const struct timeval *tv2)
{
	return timeval_add(tv1, tv2->tv_sec, tv2->tv_usec);
}

/**
  return a timeval secs/usecs into the future
*/
_PUBLIC_ struct timeval timeval_current_ofs(uint32_t secs, uint32_t usecs)
{
	struct timeval tv = timeval_current();
	return timeval_add(&tv, secs, usecs);
}

/**
  return a timeval milliseconds into the future
*/
_PUBLIC_ struct timeval timeval_current_ofs_msec(uint32_t msecs)
{
	struct timeval tv = timeval_current();
	return timeval_add(&tv, msecs / 1000, (msecs % 1000) * 1000);
}

/**
  return a timeval microseconds into the future
*/
_PUBLIC_ struct timeval timeval_current_ofs_usec(uint32_t usecs)
{
	struct timeval tv = timeval_current();
	return timeval_add(&tv, usecs / 1000000, usecs % 1000000);
}

/**
  compare two timeval structures.
  Return -1 if tv1 < tv2
  Return 0 if tv1 == tv2
  Return 1 if tv1 > tv2
*/
_PUBLIC_ int timeval_compare(const struct timeval *tv1, const struct timeval *tv2)
{
	if (tv1->tv_sec  > tv2->tv_sec)  return 1;
	if (tv1->tv_sec  < tv2->tv_sec)  return -1;
	if (tv1->tv_usec > tv2->tv_usec) return 1;
	if (tv1->tv_usec < tv2->tv_usec) return -1;
	return 0;
}

/**
  return true if a timer is in the past
*/
_PUBLIC_ bool timeval_expired(const struct timeval *tv)
{
	struct timeval tv2 = timeval_current();
	if (tv2.tv_sec > tv->tv_sec) return true;
	if (tv2.tv_sec < tv->tv_sec) return false;
	return (tv2.tv_usec >= tv->tv_usec);
}

/**
  return the number of seconds elapsed between two times
*/
_PUBLIC_ double timeval_elapsed2(const struct timeval *tv1, const struct timeval *tv2)
{
	return (tv2->tv_sec - tv1->tv_sec) +
	       (tv2->tv_usec - tv1->tv_usec)*1.0e-6;
}

/**
  return the number of seconds elapsed since a given time
*/
_PUBLIC_ double timeval_elapsed(const struct timeval *tv)
{
	struct timeval tv2 = timeval_current();
	return timeval_elapsed2(tv, &tv2);
}
/**
 *   return the number of seconds elapsed between two times
 **/
_PUBLIC_ double timespec_elapsed2(const struct timespec *ts1,
				const struct timespec *ts2)
{
	return (ts2->tv_sec - ts1->tv_sec) +
	       (ts2->tv_nsec - ts1->tv_nsec)*1.0e-9;
}

/**
 *   return the number of seconds elapsed since a given time
 */
_PUBLIC_ double timespec_elapsed(const struct timespec *ts)
{
	struct timespec ts2 = timespec_current();
	return timespec_elapsed2(ts, &ts2);
}

/**
  return the lesser of two timevals
*/
_PUBLIC_ struct timeval timeval_min(const struct timeval *tv1,
			   const struct timeval *tv2)
{
	if (tv1->tv_sec < tv2->tv_sec) return *tv1;
	if (tv1->tv_sec > tv2->tv_sec) return *tv2;
	if (tv1->tv_usec < tv2->tv_usec) return *tv1;
	return *tv2;
}

/**
  return the greater of two timevals
*/
_PUBLIC_ struct timeval timeval_max(const struct timeval *tv1,
			   const struct timeval *tv2)
{
	if (tv1->tv_sec > tv2->tv_sec) return *tv1;
	if (tv1->tv_sec < tv2->tv_sec) return *tv2;
	if (tv1->tv_usec > tv2->tv_usec) return *tv1;
	return *tv2;
}

/**
  return the difference between two timevals as a timeval
  if tv1 comes after tv2, then return a zero timeval
  (this is *tv2 - *tv1)
*/
_PUBLIC_ struct timeval timeval_until(const struct timeval *tv1,
			     const struct timeval *tv2)
{
	struct timeval t;
	if (timeval_compare(tv1, tv2) >= 0) {
		return timeval_zero();
	}
	t.tv_sec = tv2->tv_sec - tv1->tv_sec;
	if (tv1->tv_usec > tv2->tv_usec) {
		t.tv_sec--;
		t.tv_usec = 1000000 - (tv1->tv_usec - tv2->tv_usec);
	} else {
		t.tv_usec = tv2->tv_usec - tv1->tv_usec;
	}
	return t;
}


/**
  convert a timeval to a NTTIME
*/
_PUBLIC_ NTTIME timeval_to_nttime(const struct timeval *tv)
{
	return 10*(tv->tv_usec +
		  ((TIME_FIXUP_CONSTANT + (uint64_t)tv->tv_sec) * 1000000));
}

/**
  convert a NTTIME to a timeval
*/
_PUBLIC_ void nttime_to_timeval(struct timeval *tv, NTTIME t)
{
	if (tv == NULL) return;

	t += 10/2;
	t /= 10;
	t -= TIME_FIXUP_CONSTANT*1000*1000;

	tv->tv_sec  = t / 1000000;

	if (TIME_T_MIN > tv->tv_sec || tv->tv_sec > TIME_T_MAX) {
		tv->tv_sec  = 0;
		tv->tv_usec = 0;
		return;
	}

	tv->tv_usec = t - tv->tv_sec*1000000;
}

/*******************************************************************
yield the difference between *A and *B, in seconds, ignoring leap seconds
********************************************************************/
static int tm_diff(struct tm *a, struct tm *b)
{
	int ay = a->tm_year + (1900 - 1);
	int by = b->tm_year + (1900 - 1);
	int intervening_leap_days =
		(ay/4 - by/4) - (ay/100 - by/100) + (ay/400 - by/400);
	int years = ay - by;
	int days = 365*years + intervening_leap_days + (a->tm_yday - b->tm_yday);
	int hours = 24*days + (a->tm_hour - b->tm_hour);
	int minutes = 60*hours + (a->tm_min - b->tm_min);
	int seconds = 60*minutes + (a->tm_sec - b->tm_sec);

	return seconds;
}


/**
  return the UTC offset in seconds west of UTC, or 0 if it cannot be determined
 */
_PUBLIC_ int get_time_zone(time_t t)
{
	struct tm *tm = gmtime(&t);
	struct tm tm_utc;
	if (!tm)
		return 0;
	tm_utc = *tm;
	tm = localtime(&t);
	if (!tm)
		return 0;
	return tm_diff(&tm_utc,tm);
}

/*
 * Raw convert an NTTIME to a unix timespec.
 */

struct timespec nt_time_to_unix_timespec_raw(
			NTTIME nt)
{
	int64_t d;
	struct timespec ret;

	d = (int64_t)nt;
	/* d is now in 100ns units, since jan 1st 1601".
	   Save off the ns fraction. */

	/*
	 * Take the last seven decimal digits and multiply by 100.
	 * to convert from 100ns units to 1ns units.
	 */
        ret.tv_nsec = (long) ((d % (1000 * 1000 * 10)) * 100);

	/* Convert to seconds */
	d /= 1000*1000*10;

	/* Now adjust by 369 years to make the secs since 1970 */
	d -= TIME_FIXUP_CONSTANT_INT;

	ret.tv_sec = (time_t)d;
	return ret;
}

struct timespec nt_time_to_unix_timespec(NTTIME nt)
{
	struct timespec ret;

	if (nt == 0 || nt == (int64_t)-1) {
		ret.tv_sec = 0;
		ret.tv_nsec = 0;
		return ret;
	}

	ret = nt_time_to_unix_timespec_raw(nt);

	if (ret.tv_sec <= TIME_T_MIN) {
		ret.tv_sec = TIME_T_MIN;
		ret.tv_nsec = 0;
		return ret;
	}

	if (ret.tv_sec >= TIME_T_MAX) {
		ret.tv_sec = TIME_T_MAX;
		ret.tv_nsec = 0;
		return ret;
	}
	return ret;
}


/**
  check if 2 NTTIMEs are equal.
*/
bool nt_time_equal(NTTIME *t1, NTTIME *t2)
{
	return *t1 == *t2;
}

/**
 Check if it's a null timespec.
**/

bool null_timespec(struct timespec ts)
{
	return ts.tv_sec == 0 ||
		ts.tv_sec == (time_t)0xFFFFFFFF ||
		ts.tv_sec == (time_t)-1;
}

/****************************************************************************
 Convert a normalized timeval to a timespec.
****************************************************************************/

struct timespec convert_timeval_to_timespec(const struct timeval tv)
{
	struct timespec ts;
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
	return ts;
}

/****************************************************************************
 Convert a normalized timespec to a timeval.
****************************************************************************/

struct timeval convert_timespec_to_timeval(const struct timespec ts)
{
	struct timeval tv;
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / 1000;
	return tv;
}

/****************************************************************************
 Return a timespec for the current time
****************************************************************************/

_PUBLIC_ struct timespec timespec_current(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts;
}

/****************************************************************************
 Return the lesser of two timespecs.
****************************************************************************/

struct timespec timespec_min(const struct timespec *ts1,
			   const struct timespec *ts2)
{
	if (ts1->tv_sec < ts2->tv_sec) return *ts1;
	if (ts1->tv_sec > ts2->tv_sec) return *ts2;
	if (ts1->tv_nsec < ts2->tv_nsec) return *ts1;
	return *ts2;
}

/****************************************************************************
  compare two timespec structures.
  Return -1 if ts1 < ts2
  Return 0 if ts1 == ts2
  Return 1 if ts1 > ts2
****************************************************************************/

_PUBLIC_ int timespec_compare(const struct timespec *ts1, const struct timespec *ts2)
{
	if (ts1->tv_sec  > ts2->tv_sec)  return 1;
	if (ts1->tv_sec  < ts2->tv_sec)  return -1;
	if (ts1->tv_nsec > ts2->tv_nsec) return 1;
	if (ts1->tv_nsec < ts2->tv_nsec) return -1;
	return 0;
}

/****************************************************************************
 Round up a timespec if nsec > 500000000, round down if lower,
 then zero nsec.
****************************************************************************/

void round_timespec_to_sec(struct timespec *ts)
{
	ts->tv_sec = convert_timespec_to_time_t(*ts);
	ts->tv_nsec = 0;
}

/****************************************************************************
 Round a timespec to usec value.
****************************************************************************/

void round_timespec_to_usec(struct timespec *ts)
{
	struct timeval tv = convert_timespec_to_timeval(*ts);
	*ts = convert_timeval_to_timespec(tv);
	normalize_timespec(ts);
}

/****************************************************************************
 Round a timespec to NTTIME resolution.
****************************************************************************/

void round_timespec_to_nttime(struct timespec *ts)
{
	ts->tv_nsec = (ts->tv_nsec / 100) * 100;
}

/****************************************************************************
 Put a 8 byte filetime from a struct timespec. Uses GMT.
****************************************************************************/

_PUBLIC_ NTTIME unix_timespec_to_nt_time(struct timespec ts)
{
	uint64_t d;

	if (ts.tv_sec ==0 && ts.tv_nsec == 0) {
		return 0;
	}
	if (ts.tv_sec == TIME_T_MAX) {
		return 0x7fffffffffffffffLL;
	}
	if (ts.tv_sec == (time_t)-1) {
		return (uint64_t)-1;
	}

	d = ts.tv_sec;
	d += TIME_FIXUP_CONSTANT_INT;
	d *= 1000*1000*10;
	/* d is now in 100ns units. */
	d += (ts.tv_nsec / 100);

	return d;
}

/*
 * Functions supporting the full range of time_t and struct timespec values,
 * including 0, -1 and all other negative values. These functions don't use 0 or
 * -1 values as sentinel to denote "unset" variables, but use the POSIX 2008
 * define UTIME_OMIT from utimensat(2).
 */

/**
 * Check if it's a to be omitted timespec.
 **/
bool is_omit_timespec(const struct timespec *ts)
{
	return ts->tv_nsec == SAMBA_UTIME_OMIT;
}

/**
 * Return a to be omitted timespec.
 **/
struct timespec make_omit_timespec(void)
{
	return (struct timespec){.tv_nsec = SAMBA_UTIME_OMIT};
}

/**
 * Like unix_timespec_to_nt_time() but without the special casing of tv_sec=0
 * and -1. Also dealing with SAMBA_UTIME_OMIT.
 **/
NTTIME full_timespec_to_nt_time(const struct timespec *_ts)
{
	struct timespec ts = *_ts;
	uint64_t d;

	if (is_omit_timespec(_ts)) {
		return NTTIME_OMIT;
	}

	/* Ensure tv_nsec is less than 1 sec. */
	while (ts.tv_nsec > 1000000000) {
		if (ts.tv_sec > TIME_T_MAX) {
			return NTTIME_MAX;
		}
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000;
	}

	if (ts.tv_sec >= TIME_T_MAX) {
		return NTTIME_MAX;
	}
	if ((ts.tv_sec + TIME_FIXUP_CONSTANT_INT) <= 0) {
		return NTTIME_MIN;
	}

	d = TIME_FIXUP_CONSTANT_INT;
	d += ts.tv_sec;

	d *= 1000*1000*10;
	/* d is now in 100ns units. */
	d += (ts.tv_nsec / 100);

	return d;
}

/**
 * Like nt_time_to_unix_timespec() but allowing negative tv_sec values and
 * returning NTTIME=0 and -1 as struct timespec {.tv_nsec = SAMBA_UTIME_OMIT}.
 *
 * See also: is_omit_timespec().
 **/
struct timespec nt_time_to_full_timespec(NTTIME nt)
{
	struct timespec ret;

	if (nt == NTTIME_OMIT) {
		return make_omit_timespec();
	}
	if (nt == NTTIME_FREEZE || nt == NTTIME_THAW) {
		/*
		 * This should be returned as SAMBA_UTIME_FREEZE or
		 * SAMBA_UTIME_THAW in the future.
		 */
		return make_omit_timespec();
	}
	if (nt > NTTIME_MAX) {
		nt = NTTIME_MAX;
	}

	ret = nt_time_to_unix_timespec_raw(nt);

	if (ret.tv_sec >= TIME_T_MAX) {
		ret.tv_sec = TIME_T_MAX;
		ret.tv_nsec = 0;
		return ret;
	}

	return ret;
}

/**
 * Note: this function uses the full time_t range as valid date values including
 * (time_t)0 and -1. That means that struct timespec sentinel values (cf
 * is_omit_timespec()) can't be converted to sentinel values in a time_t
 * representation. Callers should therefore check the NTTIME value with
 * null_nttime() before calling this function.
 **/
time_t full_timespec_to_time_t(const struct timespec *_ts)
{
	struct timespec ts = *_ts;

	if (is_omit_timespec(_ts)) {
		/*
		 * Unfortunately there's no sensible sentinel value in the
		 * time_t range that is not conflicting with a valid time value
		 * ((time_t)0 and -1 are valid time values). Bite the bullit and
		 * return 0.
		 */
		return 0;
	}

	/* Ensure tv_nsec is less than 1sec. */
	while (ts.tv_nsec > 1000000000) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000;
	}

	/* 1 ns == 1,000,000,000 - one thousand millionths of a second.
	   increment if it's greater than 500 millionth of a second. */

	if (ts.tv_nsec > 500000000) {
		return ts.tv_sec + 1;
	}
	return ts.tv_sec;
}

/**
 * Like nt_time_to_unix() but supports negative time_t values.
 *
 * Note: this function uses the full time_t range as valid date values including
 * (time_t)0 and -1. That means that NTTIME sentinel values of 0 and -1 which
 * represent a "not-set" value, can't be converted to sentinel values in a
 * time_t representation. Callers should therefore check the NTTIME value with
 * null_nttime() before calling this function.
 **/
time_t nt_time_to_full_time_t(NTTIME nt)
{
	struct timespec ts;

	ts = nt_time_to_full_timespec(nt);
	return full_timespec_to_time_t(&ts);
}

/**
 * Like time_t_to_unix_timespec() but supports negative time_t values.
 *
 * This version converts (time_t)0 and -1 to an is_omit_timespec(), so 0 and -1
 * can't be used as valid date values. The function supports values < -1 though.
 **/
struct timespec time_t_to_full_timespec(time_t t)
{
	if (null_time(t)) {
		return (struct timespec){.tv_nsec = SAMBA_UTIME_OMIT};
	}
	return (struct timespec){.tv_sec = t};
}

#if !defined(HAVE_STAT_HIRES_TIMESTAMPS)

/* Old system - no ns timestamp. */
time_t get_atimensec(const struct stat *st)
{
	return 0;
}

time_t get_mtimensec(const struct stat *st)
{
	return 0;
}

time_t get_ctimensec(const struct stat *st)
{
	return 0;
}

/* Set does nothing with no ns timestamp. */
void set_atimensec(struct stat *st, time_t ns)
{
	return;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	return;
}

void set_ctimensec(struct stat *st, time_t ns)
{
	return;
}

#elif HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC

time_t get_atimensec(const struct stat *st)
{
	return st->st_atimespec.tv_nsec;
}

time_t get_mtimensec(const struct stat *st)
{
	return st->st_mtimespec.tv_nsec;
}

time_t get_ctimensec(const struct stat *st)
{
	return st->st_ctimespec.tv_nsec;
}

void set_atimensec(struct stat *st, time_t ns)
{
	st->st_atimespec.tv_nsec = ns;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	st->st_mtimespec.tv_nsec = ns;
}

void set_ctimensec(struct stat *st, time_t ns)
{
	st->st_ctimespec.tv_nsec = ns;
}

#elif HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC

time_t get_atimensec(const struct stat *st)
{
	return st->st_atim.tv_nsec;
}

time_t get_mtimensec(const struct stat *st)
{
	return st->st_mtim.tv_nsec;
}

time_t get_ctimensec(const struct stat *st)
{
	return st->st_ctim.tv_nsec;
}

void set_atimensec(struct stat *st, time_t ns)
{
	st->st_atim.tv_nsec = ns;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	st->st_mtim.tv_nsec = ns;
}
void set_ctimensec(struct stat *st, time_t ns)
{
	st->st_ctim.tv_nsec = ns;
}

#elif HAVE_STRUCT_STAT_ST_MTIMENSEC

time_t get_atimensec(const struct stat *st)
{
	return st->st_atimensec;
}

time_t get_mtimensec(const struct stat *st)
{
	return st->st_mtimensec;
}

time_t get_ctimensec(const struct stat *st)
{
	return st->st_ctimensec;
}

void set_atimensec(struct stat *st, time_t ns)
{
	st->st_atimensec = ns;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	st->st_mtimensec = ns;
}

void set_ctimensec(struct stat *st, time_t ns)
{
	st->st_ctimensec = ns;
}

#elif HAVE_STRUCT_STAT_ST_MTIME_N

time_t get_atimensec(const struct stat *st)
{
	return st->st_atime_n;
}

time_t get_mtimensec(const struct stat *st)
{
	return st->st_mtime_n;
}

time_t get_ctimensec(const struct stat *st)
{
	return st->st_ctime_n;
}

void set_atimensec(struct stat *st, time_t ns)
{
	st->st_atime_n = ns;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	st->st_mtime_n = ns;
}

void set_ctimensec(struct stat *st, time_t ns)
{
	st->st_ctime_n = ns;
}

#elif HAVE_STRUCT_STAT_ST_UMTIME

/* Only usec timestamps available. Convert to/from nsec. */

time_t get_atimensec(const struct stat *st)
{
	return st->st_uatime * 1000;
}

time_t get_mtimensec(const struct stat *st)
{
	return st->st_umtime * 1000;
}

time_t get_ctimensec(const struct stat *st)
{
	return st->st_uctime * 1000;
}

void set_atimensec(struct stat *st, time_t ns)
{
	st->st_uatime = ns / 1000;
}

void set_mtimensec(struct stat *st, time_t ns)
{
	st->st_umtime = ns / 1000;
}

void set_ctimensec(struct stat *st, time_t ns)
{
	st->st_uctime = ns / 1000;
}

#else
#error CONFIGURE_ERROR_IN_DETECTING_TIMESPEC_IN_STAT
#endif

struct timespec get_atimespec(const struct stat *pst)
{
	struct timespec ret;

	ret.tv_sec = pst->st_atime;
	ret.tv_nsec = get_atimensec(pst);
	return ret;
}

struct timespec get_mtimespec(const struct stat *pst)
{
	struct timespec ret;

	ret.tv_sec = pst->st_mtime;
	ret.tv_nsec = get_mtimensec(pst);
	return ret;
}

struct timespec get_ctimespec(const struct stat *pst)
{
	struct timespec ret;

	ret.tv_sec = pst->st_ctime;
	ret.tv_nsec = get_ctimensec(pst);
	return ret;
}

/****************************************************************************
 Deal with nanoseconds overflow.
****************************************************************************/

void normalize_timespec(struct timespec *ts)
{
	lldiv_t dres;

	/* most likely case: nsec is valid */
	if ((unsigned long)ts->tv_nsec < NSEC_PER_SEC) {
		return;
	}

	dres = lldiv(ts->tv_nsec, NSEC_PER_SEC);

	/* if the operation would result in overflow, max out values and bail */
	if (dres.quot > 0) {
		if ((int64_t)LONG_MAX - dres.quot < ts->tv_sec) {
			ts->tv_sec = LONG_MAX;
			ts->tv_nsec = NSEC_PER_SEC - 1;
			return;
		}
	} else {
		if ((int64_t)LONG_MIN - dres.quot > ts->tv_sec) {
			ts->tv_sec = LONG_MIN;
			ts->tv_nsec = 0;
			return;
		}
	}

	ts->tv_nsec = dres.rem;
	ts->tv_sec += dres.quot;

	/* if the ns part was positive or a multiple of -1000000000, we're done */
	if (ts->tv_nsec > 0 || dres.rem == 0) {
		return;
	}

	ts->tv_nsec += NSEC_PER_SEC;
	--ts->tv_sec;
}
