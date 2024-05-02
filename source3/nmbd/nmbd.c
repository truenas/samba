/*
   Unix SMB/CIFS implementation.
   NBT netbios routines and daemon - version 2
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 1997-2002
   Copyright (C) Jelmer Vernooij 2002,2003 (Conversion to popt)

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

#include "includes.h"
#include "system/filesys.h"
#include "lib/cmdline/cmdline.h"
#include "nmbd/nmbd.h"
#include "serverid.h"
#include "messages.h"
#include "../lib/util/pidfile.h"
#include "util_cluster.h"
#include "lib/gencache.h"
#include "lib/global_contexts.h"
#include "source3/lib/substitute.h"

int ClientNMB       = -1;
int ClientDGRAM     = -1;
int global_nmb_port = -1;

extern bool rescan_listen_set;
extern bool global_in_nmbd;

/* have we found LanMan clients yet? */
bool found_lm_clients = False;

/* what server type are we currently */

time_t StartupTime = 0;

struct tevent_context *nmbd_event_context(void)
{
	return global_event_context();
}

/**************************************************************************** **
 Handle a SIGTERM in band.
 **************************************************************************** */

static void terminate(struct messaging_context *msg)
{
	DBG_WARNING("Got SIGTERM: going down...\n");

	/* Write out wins.dat file if samba is a WINS server */
	wins_write_database(0,False);

	/* Remove all SELF registered names from WINS */
	release_wins_names();

	/* Announce all server entries as 0 time-to-live, 0 type. */
	announce_my_servers_removed();

	/* If there was an async dns child - kill it. */
	kill_async_dns_child();

	pidfile_unlink(lp_pid_directory(), "nmbd");

	exit(0);
}

static void nmbd_sig_term_handler(struct tevent_context *ev,
				  struct tevent_signal *se,
				  int signum,
				  int count,
				  void *siginfo,
				  void *private_data)
{
	struct messaging_context *msg = talloc_get_type_abort(
		private_data, struct messaging_context);

	terminate(msg);
}

/*
  handle stdin becoming readable when we are in --foreground mode
 */
static void nmbd_stdin_handler(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data)
{
	char c;
	if (read(0, &c, 1) != 1) {
		struct messaging_context *msg = talloc_get_type_abort(
			private_data, struct messaging_context);

		DBG_WARNING("EOF on stdin\n");
		terminate(msg);
	}
}

static bool nmbd_setup_sig_term_handler(struct messaging_context *msg)
{
	struct tevent_signal *se;

	se = tevent_add_signal(nmbd_event_context(),
			       nmbd_event_context(),
			       SIGTERM, 0,
			       nmbd_sig_term_handler,
			       msg);
	if (!se) {
		DBG_ERR("failed to setup SIGTERM handler");
		return false;
	}

	return true;
}

static bool nmbd_setup_stdin_handler(struct messaging_context *msg, bool foreground)
{
	if (foreground) {
		/* if we are running in the foreground then look for
		   EOF on stdin, and exit if it happens. This allows
		   us to die if the parent process dies
		   Only do this on a pipe or socket, no other device.
		*/
		struct stat st;
		if (fstat(0, &st) != 0) {
			return false;
		}
		if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
			tevent_add_fd(nmbd_event_context(),
				nmbd_event_context(),
				0,
				TEVENT_FD_READ,
				nmbd_stdin_handler,
				msg);
		}
	}

	return true;
}

static void msg_reload_nmbd_services(struct messaging_context *msg,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id server_id,
				     DATA_BLOB *data);

static void nmbd_sig_hup_handler(struct tevent_context *ev,
				 struct tevent_signal *se,
				 int signum,
				 int count,
				 void *siginfo,
				 void *private_data)
{
	struct messaging_context *msg = talloc_get_type_abort(
		private_data, struct messaging_context);

	DBG_WARNING("Got SIGHUP dumping debug info.\n");
	msg_reload_nmbd_services(msg, NULL, MSG_SMB_CONF_UPDATED,
				 messaging_server_id(msg), NULL);
}

static bool nmbd_setup_sig_hup_handler(struct messaging_context *msg)
{
	struct tevent_signal *se;

	se = tevent_add_signal(nmbd_event_context(),
			       nmbd_event_context(),
			       SIGHUP, 0,
			       nmbd_sig_hup_handler,
			       msg);
	if (!se) {
		DBG_ERR("failed to setup SIGHUP handler");
		return false;
	}

	return true;
}

/**************************************************************************** **
 Handle a SHUTDOWN message from smbcontrol.
 **************************************************************************** */

static void nmbd_terminate(struct messaging_context *msg,
			   void *private_data,
			   uint32_t msg_type,
			   struct server_id server_id,
			   DATA_BLOB *data)
{
	terminate(msg);
}

/**************************************************************************** **
 Expire old names from the namelist and server list.
 **************************************************************************** */

static void expire_names_and_servers(time_t t)
{
	static time_t lastrun = 0;

	if ( !lastrun )
		lastrun = t;
	if ( t < (lastrun + 5) )
		return;
	lastrun = t;

	/*
	 * Expire any timed out names on all the broadcast
	 * subnets and those registered with the WINS server.
	 * (nmbd_namelistdb.c)
	 */

	expire_names(t);

	/*
	 * Go through all the broadcast subnets and for each
	 * workgroup known on that subnet remove any expired
	 * server names. If a workgroup has an empty serverlist
	 * and has itself timed out then remove the workgroup.
	 * (nmbd_workgroupdb.c)
	 */

	expire_workgroups_and_servers(t);
}

/************************************************************************** **
 Reload the list of network interfaces.
 Doesn't return until a network interface is up.
 ************************************************************************** */

static void reload_interfaces(time_t t)
{
	static time_t lastt;
	int n;
	bool print_waiting_msg = true;
	struct subnet_record *subrec;

	if (t && ((t - lastt) < NMBD_INTERFACES_RELOAD)) {
		return;
	}

	lastt = t;

	if (!interfaces_changed()) {
		return;
	}

  try_again:

	/* the list of probed interfaces has changed, we may need to add/remove
	   some subnets */
	load_interfaces();

	/* find any interfaces that need adding */
	for (n=iface_count() - 1; n >= 0; n--) {
		char str[INET6_ADDRSTRLEN];
		const struct interface *iface = get_interface(n);
		struct in_addr ip, nmask;

		if (!iface) {
			DBG_WARNING("reload_interfaces: failed to get interface %d\n", n);
			continue;
		}

		/* Ensure we're only dealing with IPv4 here. */
		if (iface->ip.ss_family != AF_INET) {
			DBG_NOTICE("reload_interfaces: "
				"ignoring non IPv4 interface.\n");
			continue;
		}

		ip = ((const struct sockaddr_in *)(const void *)&iface->ip)->sin_addr;
		nmask = ((const struct sockaddr_in *)(const void *)
			 &iface->netmask)->sin_addr;

		/*
		 * We don't want to add a loopback interface, in case
		 * someone has added 127.0.0.1 for smbd, nmbd needs to
		 * ignore it here. JRA.
		 */

		if (is_loopback_addr((const struct sockaddr *)(const void *)&iface->ip)) {
			DBG_NOTICE("reload_interfaces: Ignoring loopback "
				"interface %s\n",
				print_sockaddr(str, sizeof(str), &iface->ip) );
			continue;
		}

		for (subrec=subnetlist; subrec; subrec=subrec->next) {
			if (ip_equal_v4(ip, subrec->myip) &&
			    ip_equal_v4(nmask, subrec->mask_ip)) {
				break;
			}
		}

		if (!subrec) {
			/* it wasn't found! add it */
			DBG_NOTICE("Found new interface %s\n",
				 print_sockaddr(str,
					 sizeof(str), &iface->ip) );
			subrec = make_normal_subnet(iface);
			if (subrec)
				register_my_workgroup_one_subnet(subrec);
		}
	}

	/* find any interfaces that need deleting */
	for (subrec=subnetlist; subrec; subrec=subrec->next) {
		for (n=iface_count() - 1; n >= 0; n--) {
			struct interface *iface = get_interface(n);
			struct in_addr ip, nmask;
			if (!iface) {
				continue;
			}
			/* Ensure we're only dealing with IPv4 here. */
			if (iface->ip.ss_family != AF_INET) {
				DBG_NOTICE("reload_interfaces: "
					"ignoring non IPv4 interface.\n");
				continue;
			}
			ip = ((struct sockaddr_in *)(void *)
			      &iface->ip)->sin_addr;
			nmask = ((struct sockaddr_in *)(void *)
				 &iface->netmask)->sin_addr;
			if (ip_equal_v4(ip, subrec->myip) &&
			    ip_equal_v4(nmask, subrec->mask_ip)) {
				break;
			}
		}
		if (n == -1) {
			/* oops, an interface has disappeared. This is
			 tricky, we don't dare actually free the
			 interface as it could be being used, so
			 instead we just wear the memory leak and
			 remove it from the list of interfaces without
			 freeing it */
			DBG_NOTICE("Deleting dead interface %s\n",
				 inet_ntoa(subrec->myip));
			close_subnet(subrec);
		}
	}

	rescan_listen_set = True;

	/* We need to wait if there are no subnets... */
	if (FIRST_SUBNET == NULL) {
		void (*saved_handler)(int);

		if (print_waiting_msg) {
			DBG_WARNING("reload_interfaces: "
				"No subnets to listen to. Waiting..\n");
			print_waiting_msg = false;
		}

		/*
		 * Whilst we're waiting for an interface, allow SIGTERM to
		 * cause us to exit.
		 */
		saved_handler = CatchSignal(SIGTERM, SIG_DFL);

		/* We only count IPv4, non-loopback interfaces here. */
		while (iface_count_v4_nl() == 0) {
			usleep(NMBD_WAIT_INTERFACES_TIME_USEC);
			load_interfaces();
		}

		CatchSignal(SIGTERM, saved_handler);

		/*
		 * We got an interface, go back to blocking term.
		 */

		goto try_again;
	}
}

/**************************************************************************** **
 Reload the services file.
 **************************************************************************** */

static bool reload_nmbd_services(bool test)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	bool ret;

	set_remote_machine_name("nmbd", False);

	if ( lp_loaded() ) {
		char *fname = lp_next_configfile(talloc_tos(), lp_sub);
		if (file_exist(fname) && !strcsequal(fname,get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
			test = False;
		}
		TALLOC_FREE(fname);
	}

	if ( test && !lp_file_list_changed() )
		return(True);

	ret = lp_load_global(get_dyn_CONFIGFILE());

	/* perhaps the config filename is now set */
	if ( !test ) {
		DBG_NOTICE( "services not loaded\n" );
		reload_nmbd_services( True );
	}

	reopen_logs();

	return(ret);
}

/**************************************************************************** **
 * React on 'smbcontrol nmbd reload-config' in the same way as to SIGHUP
 **************************************************************************** */

static void msg_reload_nmbd_services(struct messaging_context *msg,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id server_id,
				     DATA_BLOB *data)
{
	write_browse_list( 0, True );
	dump_all_namelists();
	reload_nmbd_services( True );
	reopen_logs();
	reload_interfaces(0);
	nmbd_init_my_netbios_names();
}

static void msg_nmbd_send_packet(struct messaging_context *msg,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id src,
				 DATA_BLOB *data)
{
	struct packet_struct *p = (struct packet_struct *)data->data;
	struct subnet_record *subrec;
	struct sockaddr_storage ss;
	const struct sockaddr_storage *pss;
	const struct in_addr *local_ip;

	DBG_DEBUG("Received send_packet from %u\n", (unsigned int)procid_to_pid(&src));

	if (data->length != sizeof(struct packet_struct)) {
		DBG_WARNING("Discarding invalid packet length from %u\n",
			  (unsigned int)procid_to_pid(&src));
		return;
	}

	if ((p->packet_type != NMB_PACKET) &&
	    (p->packet_type != DGRAM_PACKET)) {
		DBG_WARNING("Discarding invalid packet type from %u: %d\n",
			  (unsigned int)procid_to_pid(&src), p->packet_type);
		return;
	}

	in_addr_to_sockaddr_storage(&ss, p->ip);
	pss = iface_ip((struct sockaddr *)(void *)&ss);

	if (pss == NULL) {
		DBG_WARNING("Could not find ip for packet from %u\n",
			  (unsigned int)procid_to_pid(&src));
		return;
	}

	local_ip = &((const struct sockaddr_in *)pss)->sin_addr;
	subrec = FIRST_SUBNET;

	p->recv_fd = -1;
	p->send_fd = (p->packet_type == NMB_PACKET) ?
		subrec->nmb_sock : subrec->dgram_sock;

	for (subrec = FIRST_SUBNET; subrec != NULL;
	     subrec = NEXT_SUBNET_EXCLUDING_UNICAST(subrec)) {
		if (ip_equal_v4(*local_ip, subrec->myip)) {
			p->send_fd = (p->packet_type == NMB_PACKET) ?
				subrec->nmb_sock : subrec->dgram_sock;
			break;
		}
	}

	if (p->packet_type == DGRAM_PACKET) {
		p->port = 138;
		p->packet.dgram.header.source_ip.s_addr = local_ip->s_addr;
		p->packet.dgram.header.source_port = 138;
	}

	send_packet(p);
}

/**************************************************************************** **
 The main select loop.
 **************************************************************************** */

static void process(struct messaging_context *msg)
{
	bool run_election;

	while( True ) {
		time_t t = time(NULL);
		TALLOC_CTX *frame = talloc_stackframe();

		/*
		 * Check all broadcast subnets to see if
		 * we need to run an election on any of them.
		 * (nmbd_elections.c)
		 */

		run_election = check_elections();

		/*
		 * Read incoming UDP packets.
		 * (nmbd_packets.c)
		 */

		if (listen_for_packets(msg, run_election)) {
			TALLOC_FREE(frame);
			return;
		}

		/*
		 * Process all incoming packets
		 * read above. This calls the success and
		 * failure functions registered when response
		 * packets arrive, and also deals with request
		 * packets from other sources.
		 * (nmbd_packets.c)
		 */

		run_packet_queue();

		/*
		 * Run any elections - initiate becoming
		 * a local master browser if we have won.
		 * (nmbd_elections.c)
		 */

		run_elections(t);

		/*
		 * Send out any broadcast announcements
		 * of our server names. This also announces
		 * the workgroup name if we are a local
		 * master browser.
		 * (nmbd_sendannounce.c)
		 */

		announce_my_server_names(t);

		/*
		 * Send out any LanMan broadcast announcements
		 * of our server names.
		 * (nmbd_sendannounce.c)
		 */

		announce_my_lm_server_names(t);

		/*
		 * If we are a local master browser, periodically
		 * announce ourselves to the domain master browser.
		 * This also deals with synchronising the domain master
		 * browser server lists with ourselves as a local
		 * master browser.
		 * (nmbd_sendannounce.c)
		 */

		announce_myself_to_domain_master_browser(t);

		/*
		 * Fulfill any remote announce requests.
		 * (nmbd_sendannounce.c)
		 */

		announce_remote(t);

		/*
		 * Fulfill any remote browse sync announce requests.
		 * (nmbd_sendannounce.c)
		 */

		browse_sync_remote(t);

		/*
		 * Scan the broadcast subnets, and WINS client
		 * namelists and refresh any that need refreshing.
		 * (nmbd_mynames.c)
		 */

		refresh_my_names(t);

		/*
		 * Scan the subnet namelists and server lists and
		 * expire those that have timed out.
		 * (nmbd.c)
		 */

		expire_names_and_servers(t);

		/*
		 * Write out a snapshot of our current browse list into
		 * the browse.dat file. This is used by smbd to service
		 * incoming NetServerEnum calls - used to synchronise
		 * browse lists over subnets.
		 * (nmbd_serverlistdb.c)
		 */

		write_browse_list(t, False);

		/*
		 * If we are a domain master browser, we have a list of
		 * local master browsers we should synchronise browse
		 * lists with (these are added by an incoming local
		 * master browser announcement packet). Expire any of
		 * these that are no longer current, and pull the server
		 * lists from each of these known local master browsers.
		 * (nmbd_browsesync.c)
		 */

		dmb_expire_and_sync_browser_lists(t);

		/*
		 * Check that there is a local master browser for our
		 * workgroup for all our broadcast subnets. If one
		 * is not found, start an election (which we ourselves
		 * may or may not participate in, depending on the
		 * setting of the 'local master' parameter.
		 * (nmbd_elections.c)
		 */

		check_master_browser_exists(t);

		/*
		 * If we are configured as a logon server, attempt to
		 * register the special NetBIOS names to become such
		 * (WORKGROUP<1c> name) on all broadcast subnets and
		 * with the WINS server (if used). If we are configured
		 * to become a domain master browser, attempt to register
		 * the special NetBIOS name (WORKGROUP<1b> name) to
		 * become such.
		 * (nmbd_become_dmb.c)
		 */

		add_domain_names(t);

		/*
		 * If we are a WINS server, do any timer dependent
		 * processing required.
		 * (nmbd_winsserver.c)
		 */

		initiate_wins_processing(t);

		/*
		 * If we are a domain master browser, attempt to contact the
		 * WINS server to get a list of all known WORKGROUPS/DOMAINS.
		 * This will only work to a Samba WINS server.
		 * (nmbd_browsesync.c)
		 */

		if (lp_enhanced_browsing())
			collect_all_workgroup_names_from_wins_server(t);

		/*
		 * Go through the response record queue and time out or re-transmit
		 * and expired entries.
		 * (nmbd_packets.c)
		 */

		retransmit_or_expire_response_records(t);

		/*
		 * check to see if any remote browse sync child processes have completed
		 */

		sync_check_completion();

		/*
		 * regularly sync with any other DMBs we know about
		 */

		if (lp_enhanced_browsing())
			sync_all_dmbs(t);

		/* check for new network interfaces */

		reload_interfaces(t);

		/* free up temp memory */
		TALLOC_FREE(frame);
	}
}

/**************************************************************************** **
 Open the socket communication.
 **************************************************************************** */

static bool open_sockets(bool isdaemon, int port)
{
	struct sockaddr_storage ss;
	const char *sock_addr = lp_nbt_client_socket_address();

	/*
	 * The sockets opened here will be used to receive broadcast
	 * packets *only*. Interface specific sockets are opened in
	 * make_subnet() in namedbsubnet.c. Thus we bind to the
	 * address "0.0.0.0". The parameter 'socket address' is
	 * now deprecated.
	 */

	if (!interpret_string_addr(&ss, sock_addr,
				AI_NUMERICHOST|AI_PASSIVE)) {
		DBG_ERR("open_sockets: unable to get socket address "
			"from string %s", sock_addr);
		return false;
	}
	if (ss.ss_family != AF_INET) {
		DBG_ERR("open_sockets: unable to use IPv6 socket"
			"%s in nmbd\n",
			sock_addr);
		return false;
	}

	if (isdaemon) {
		ClientNMB = open_socket_in(SOCK_DGRAM, &ss, port, true);
	} else {
		ClientNMB = 0;
	}

	if (ClientNMB < 0) {
		return false;
	}

	ClientDGRAM = open_socket_in(SOCK_DGRAM, &ss, DGRAM_PORT, true);

	if (ClientDGRAM < 0) {
		if (ClientNMB != 0) {
			close(ClientNMB);
		}
		return false;
	}

	/* we are never interested in SIGPIPE */
	BlockSignals(True,SIGPIPE);

	set_socket_options( ClientNMB,   "SO_BROADCAST" );
	set_socket_options( ClientDGRAM, "SO_BROADCAST" );

	/* Ensure we're non-blocking. */
	set_blocking( ClientNMB, False);
	set_blocking( ClientDGRAM, False);

	DBG_INFO( "open_sockets: Broadcast sockets opened.\n" );
	return( True );
}

/**************************************************************************** **
 main program
 **************************************************************************** */

 int main(int argc, const char *argv[])
{
	struct samba_cmdline_daemon_cfg *cmdline_daemon_cfg = NULL;
	bool log_stdout = false;
	poptContext pc;
	char *p_lmhosts = NULL;
	int opt;
	struct messaging_context *msg;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "hosts",
			.shortName  = 'H',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &p_lmhosts,
			.val        = 0,
			.descrip    = "Load a netbios hosts file",
		},
		{
			.longName   = "port",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_INT,
			.arg        = &global_nmb_port,
			.val        = 0,
			.descrip    = "Listen on the specified port",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_DAEMON
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	TALLOC_CTX *frame;
	NTSTATUS status;
	bool ok;

	/*
	 * Do this before any other talloc operation
	 */
	talloc_enable_null_tracking();
	frame = talloc_stackframe();

	/*
	 * We want total control over the permissions on created files,
	 * so set our umask to 0.
	 */
	umask(0);

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_SERVER,
				true /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(ENOMEM);
	}

	cmdline_daemon_cfg = samba_cmdline_get_daemon_cfg();

	global_nmb_port = NMB_PORT;

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		d_fprintf(stderr, "\nInvalid options\n\n");
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	};
	poptFreeContext(pc);

	global_in_nmbd = true;

	StartupTime = time(NULL);

	sys_srandom(time(NULL) ^ getpid());

	if (is_default_dyn_LOGFILEBASE()) {
		char *lfile = NULL;
		if (asprintf(&lfile, "%s/log.nmbd", get_dyn_LOGFILEBASE()) < 0) {
			exit(1);
		}
		lp_set_logfile(lfile);
		SAFE_FREE(lfile);
	}

	dump_core_setup("nmbd", lp_logfile(talloc_tos(), lp_sub));

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't receive them. */
	BlockSignals(False, SIGHUP);
	BlockSignals(False, SIGUSR1);
	BlockSignals(False, SIGTERM);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(True,SIGFPE);
#endif

	/* We no longer use USR2... */
#if defined(SIGUSR2)
	BlockSignals(True, SIGUSR2);
#endif

	/* Ignore children - no zombies. */
	CatchChild();

	log_stdout = (debug_get_log_type() == DEBUG_STDOUT);
	if ( cmdline_daemon_cfg->interactive ) {
		log_stdout = True;
	}

	if ( log_stdout && cmdline_daemon_cfg->fork ) {
		DBG_ERR("ERROR: Can't log to stdout (-S) unless daemon is in foreground (-F) or interactive (-i)\n");
		exit(1);
	}

	reopen_logs();

	DBG_STARTUP_NOTICE("nmbd version %s started.\n%s\n",
			   samba_version_string(),
			   samba_copyright_string());

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC
	    && !lp_parm_bool(-1, "server role check", "inhibit", false)) {
		/* TODO: when we have a merged set of defaults for
		 * loadparm, we could possibly check if the internal
		 * nbt server is in the list, and allow a startup if disabled */
		DBG_ERR("server role = 'active directory domain controller' not compatible with running nmbd standalone.\n"
		        "You should start 'samba' instead, and it will control starting the internal nbt server\n");
		exit(1);
	}

	if (!cluster_probe_ok()) {
		exit(1);
	}

	msg = messaging_init(NULL, global_event_context());
	if (msg == NULL) {
		DBG_ERR("Failed to init messaging context!\n");
		return 1;
	}

	if ( !reload_nmbd_services(False) )
		return(-1);

	if (!nmbd_init_my_netbios_names()) {
		return -1;
	}

	reload_nmbd_services( True );

	if (strequal(lp_workgroup(),"*")) {
		DBG_ERR("ERROR: a workgroup name of * is no longer supported\n");
		exit(1);
	}

	set_samba_nb_type();

	if (!cmdline_daemon_cfg->daemon && !is_a_socket(0)) {
		DBG_NOTICE("standard input is not a socket, assuming -D option\n");
		cmdline_daemon_cfg->daemon = true;
	}

	if (cmdline_daemon_cfg->daemon && !cmdline_daemon_cfg->interactive) {
		DBG_NOTICE("Becoming a daemon.\n");
		become_daemon(cmdline_daemon_cfg->fork,
			      cmdline_daemon_cfg->no_process_group,
			      log_stdout);
	} else if (!cmdline_daemon_cfg->interactive) {
		daemon_status("nmbd", "Starting process...");
	}

#ifdef HAVE_SETPGID
	/*
	 * If we're interactive we want to set our own process group for
	 * signal management.
	 */
	if (cmdline_daemon_cfg->interactive &&
	    !cmdline_daemon_cfg->no_process_group)
	{
		setpgid( (pid_t)0, (pid_t)0 );
	}
#endif

#ifndef SYNC_DNS
	/* Setup the async dns. We do it here so it doesn't have all the other
		stuff initialised and thus chewing memory and sockets */
	if(lp_we_are_a_wins_server() && lp_wins_dns_proxy()) {
		start_async_dns(msg);
	}
#endif

	ok = directory_create_or_exist(lp_lock_directory(), 0755);
	if (!ok) {
		exit_daemon("Failed to create directory for lock files, check 'lock directory'", errno);
	}

	ok = directory_create_or_exist(lp_pid_directory(), 0755);
	if (!ok) {
		exit_daemon("Failed to create directory for pid files, check 'pid directory'", errno);
	}

	pidfile_create(lp_pid_directory(), "nmbd");

	status = reinit_after_fork(msg, nmbd_event_context(), false);

	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon("reinit_after_fork() failed", map_errno_from_nt_status(status));
	}

	/*
	 * Do not initialize the parent-child-pipe before becoming
	 * a daemon: this is used to detect a died parent in the child
	 * process.
	 */
	status = init_before_fork();
	if (!NT_STATUS_IS_OK(status)) {
		exit_daemon(nt_errstr(status), map_errno_from_nt_status(status));
	}

	if (!nmbd_setup_sig_term_handler(msg))
		exit_daemon("NMBD failed to setup signal handler", EINVAL);
	if (!nmbd_setup_stdin_handler(msg, !cmdline_daemon_cfg->fork))
		exit_daemon("NMBD failed to setup stdin handler", EINVAL);
	if (!nmbd_setup_sig_hup_handler(msg))
		exit_daemon("NMBD failed to setup SIGHUP handler", EINVAL);

	if (!messaging_parent_dgm_cleanup_init(msg)) {
		exit(1);
	}

	messaging_register(msg, NULL, MSG_FORCE_ELECTION,
			   nmbd_message_election);
#if 0
	/* Until winsrepl is done. */
	messaging_register(msg, NULL, MSG_WINS_NEW_ENTRY,
			   nmbd_wins_new_entry);
#endif
	messaging_register(msg, NULL, MSG_SHUTDOWN,
			   nmbd_terminate);
	messaging_register(msg, NULL, MSG_SMB_CONF_UPDATED,
			   msg_reload_nmbd_services);
	messaging_register(msg, NULL, MSG_SEND_PACKET,
			   msg_nmbd_send_packet);

	TimeInit();

	DBG_NOTICE("Opening sockets %d\n", global_nmb_port);

	if ( !open_sockets( cmdline_daemon_cfg->daemon, global_nmb_port ) ) {
		kill_async_dns_child();
		return 1;
	}

	/* Determine all the IP addresses we have. */
	load_interfaces();

	/* Create an nmbd subnet record for each of the above. */
	if( False == create_subnets() ) {
		kill_async_dns_child();
		exit_daemon("NMBD failed when creating subnet lists", EACCES);
	}

	/* Load in any static local names. */
	if (p_lmhosts) {
		set_dyn_LMHOSTSFILE(p_lmhosts);
	}
	load_lmhosts_file(get_dyn_LMHOSTSFILE());
	DBG_NOTICE("Loaded hosts file %s\n", get_dyn_LMHOSTSFILE());

	/* If we are acting as a WINS server, initialise data structures. */
	if( !initialise_wins() ) {
		kill_async_dns_child();
		exit_daemon( "NMBD failed when initialising WINS server.", EACCES);
	}

	/*
	 * Register nmbd primary workgroup and nmbd names on all
	 * the broadcast subnets, and on the WINS server (if specified).
	 * Also initiate the startup of our primary workgroup (start
	 * elections if we are setup as being able to be a local
	 * master browser.
	 */

	if( False == register_my_workgroup_and_names() ) {
		kill_async_dns_child();
		exit_daemon( "NMBD failed when creating my workgroup.", EACCES);
	}

	if (!initialize_nmbd_proxy_logon()) {
		kill_async_dns_child();
		exit_daemon( "NMBD failed to setup nmbd_proxy_logon.", EACCES);
	}

	if (!nmbd_init_packet_server()) {
		kill_async_dns_child();
		exit_daemon( "NMBD failed to setup packet server.", EACCES);
	}

	if (!cmdline_daemon_cfg->interactive) {
		daemon_ready("nmbd");
	}

	TALLOC_FREE(frame);
	process(msg);

	kill_async_dns_child();
	return(0);
}
