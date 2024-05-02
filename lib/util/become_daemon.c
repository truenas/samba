/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   
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
#include "system/filesys.h"
#include "system/locale.h"
#if defined(HAVE_LIBSYSTEMD_DAEMON) || defined(HAVE_LIBSYSTEMD)
#include <systemd/sd-daemon.h>
#endif

#include "close_low_fd.h"
#include "debug.h"

#include "become_daemon.h"

static bool sd_notifications = true;

/*******************************************************************
 Enable or disable daemon status systemd notifications
********************************************************************/
void daemon_sd_notifications(bool enable)
{
	sd_notifications = enable;
	DBG_DEBUG("Daemon status systemd notifications %s\n",
		  sd_notifications ? "enabled" : "disabled");
}

/****************************************************************************
 Become a daemon, discarding the controlling terminal.
****************************************************************************/

void become_daemon(bool do_fork, bool no_session, bool log_stdout)
{
	pid_t newpid;
	if (do_fork) {
		newpid = fork();
		if (newpid == -1) {
			exit_daemon("Fork failed", errno);
		}
		if (newpid) {
			_exit(0);
		}
#if defined(HAVE_LIBSYSTEMD_DAEMON) || defined(HAVE_LIBSYSTEMD)
	} else if (sd_notifications) {
		sd_notify(0, "STATUS=Starting process...");
#endif
	}

	/* detach from the terminal */
#ifdef HAVE_SETSID
	if (!no_session) {
		int ret = setsid();
		if (ret == -1) {
			exit_daemon("Failed to create session", errno);
		}
	}
#elif defined(TIOCNOTTY)
	if (!no_session) {
		int i = open("/dev/tty", O_RDWR, 0);
		if (i != -1) {
			ioctl(i, (int) TIOCNOTTY, (char *)0);
			close(i);
		}
	}
#endif /* HAVE_SETSID */

	/* Close fd's 0,1,2 as appropriate. Needed if started by rsh. */
	/* stdin must be open if we do not fork, for monitoring for
	 * close.  stdout must be open if we are logging there, and we
	 * never close stderr (but debug might dup it onto a log file) */
	if (do_fork) {
		int ret = close_low_fd(0);
		if (ret != 0) {
			exit_daemon("close_low_fd(0) failed: %s\n", errno);
		}
	}
	if (!log_stdout) {
		int ret = close_low_fd(1);
		if (ret != 0) {
			exit_daemon("close_low_fd(1) failed: %s\n", errno);
		}
	}
}

void exit_daemon(const char *msg, int error)
{
	if (msg == NULL) {
		msg = strerror(error);
	}

#if defined(HAVE_LIBSYSTEMD_DAEMON) || defined(HAVE_LIBSYSTEMD)
	if (sd_notifications) {
		sd_notifyf(0, "STATUS=daemon failed to start: %s\n"
				  "ERRNO=%i",
				  msg,
				  error);
	}
#endif
	DBG_ERR("daemon failed to start: %s, error code %d\n",
		msg, error);
	exit(1);
}

void daemon_ready(const char *daemon)
{
	if (daemon == NULL) {
		daemon = "Samba";
	}
#if defined(HAVE_LIBSYSTEMD_DAEMON) || defined(HAVE_LIBSYSTEMD)
	if (sd_notifications) {
		sd_notifyf(0,
			   "READY=1\nSTATUS=%s: ready to serve connections...",
			   daemon);
	}
#endif
	DBG_INFO("daemon '%s' finished starting up and ready to serve "
		"connections\n", daemon);
}

void daemon_status(const char *daemon, const char *msg)
{
	if (daemon == NULL) {
		daemon = "Samba";
	}
#if defined(HAVE_LIBSYSTEMD_DAEMON) || defined(HAVE_LIBSYSTEMD)
	if (sd_notifications) {
		sd_notifyf(0, "STATUS=%s: %s", daemon, msg);
	}
#endif
	DBG_STARTUP_NOTICE("daemon '%s' : %s\n", daemon, msg);
}
