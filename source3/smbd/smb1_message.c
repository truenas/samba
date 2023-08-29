/* 
   Unix SMB/CIFS implementation.
   SMB messaging
   Copyright (C) Andrew Tridgell 1992-1998
   
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
/*
   This file handles the messaging system calls for winpopup style
   messages
*/


#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbprofile.h"
#include "source3/lib/substitute.h"

struct msg_state {
	char *from;
	char *to;
	char *msg;
};

/****************************************************************************
 Deliver the message.
****************************************************************************/

static void msg_deliver(struct msg_state *state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *name = NULL;
	int i;
	int fd;
	char *msg;
	size_t len;
	ssize_t sz;
	fstring alpha_buf;
	char *s;
	mode_t mask;

	if (! (*lp_message_command(frame, lp_sub))) {
		DEBUG(1,("no messaging command specified\n"));
		goto done;
	}

	/* put it in a temporary file */
	name = talloc_asprintf(talloc_tos(), "%s/msg.XXXXXX", tmpdir());
	if (!name) {
		goto done;
	}
	mask = umask(S_IRWXO | S_IRWXG);
	fd = mkstemp(name);
	umask(mask);

	if (fd == -1) {
		DEBUG(1, ("can't open message file %s: %s\n", name,
			  strerror(errno)));
		goto done;
	}

	/*
	 * Incoming message is in DOS codepage format. Convert to UNIX.
	 */

	if (!convert_string_talloc(talloc_tos(), CH_DOS, CH_UNIX, state->msg,
				   talloc_get_size(state->msg), (void *)&msg,
				   &len)) {
		DEBUG(3, ("Conversion failed, delivering message in DOS "
			  "codepage format\n"));
		msg = state->msg;
	}

	for (i = 0; i < len; i++) {
		if ((msg[i] == '\r') &&
		    (i < (len-1)) && (msg[i+1] == '\n')) {
			continue;
		}
		sz = write(fd, &msg[i], 1);
		if ( sz != 1 ) {
			DEBUG(0, ("Write error to fd %d: %ld(%s)\n", fd,
				  (long)sz, strerror(errno)));
		}
	}

	close(fd);

	/* run the command */
	s = lp_message_command(frame, lp_sub);
	if (s == NULL) {
		goto done;
	}

	alpha_strcpy(alpha_buf, state->from, NULL, sizeof(alpha_buf));

	s = talloc_string_sub(talloc_tos(), s, "%f", alpha_buf);
	if (s == NULL) {
		goto done;
	}

	alpha_strcpy(alpha_buf, state->to, NULL, sizeof(alpha_buf));

	s = talloc_string_sub(talloc_tos(), s, "%t", alpha_buf);
	if (s == NULL) {
		goto done;
	}

	s = talloc_sub_basic(talloc_tos(), get_current_username(),
			     get_current_user_info_domain(), s);
	if (s == NULL) {
		goto done;
	}

	s = talloc_string_sub(talloc_tos(), s, "%s", name);
	if (s == NULL) {
		goto done;
	}
	smbrun(s, NULL, NULL);

 done:
	TALLOC_FREE(frame);
	return;
}

/****************************************************************************
 Reply to a sends.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_sends(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct msg_state *state;
	int len;
	const uint8_t *msg;
	const uint8_t *p;

	START_PROFILE(SMBsends);

	if (!(*lp_message_command(talloc_tos(), lp_sub))) {
		reply_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		END_PROFILE(SMBsends);
		return;
	}

	state = talloc_zero(talloc_tos(), struct msg_state);

	p = req->buf + 1;
	p += srvstr_pull_req_talloc(
		state, req, &state->from, p, STR_ASCII|STR_TERMINATE) + 1;
	p += srvstr_pull_req_talloc(
		state, req, &state->to, p, STR_ASCII|STR_TERMINATE) + 1;

	msg = p;

	len = SVAL(msg,0);
	len = MIN(len, smbreq_bufrem(req, msg+2));

	state->msg = talloc_array(state, char, len);

	if (state->msg == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBsends);
		return;
	}

	memcpy(state->msg, msg+2, len);

	msg_deliver(state);

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsends);
	return;
}

/****************************************************************************
 Reply to a sendstrt.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_sendstrt(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *xconn = req->xconn;
	const uint8_t *p;

	START_PROFILE(SMBsendstrt);

	if (!(*lp_message_command(talloc_tos(), lp_sub))) {
		reply_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		END_PROFILE(SMBsendstrt);
		return;
	}

	TALLOC_FREE(xconn->smb1.msg_state);

	xconn->smb1.msg_state = talloc_zero(xconn, struct msg_state);

	if (xconn->smb1.msg_state == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBsendstrt);
		return;
	}

	p = req->buf+1;
	p += srvstr_pull_req_talloc(
		xconn->smb1.msg_state, req,
		&xconn->smb1.msg_state->from, p,
		STR_ASCII|STR_TERMINATE) + 1;
	p += srvstr_pull_req_talloc(
		xconn->smb1.msg_state, req,
		&xconn->smb1.msg_state->to, p,
		STR_ASCII|STR_TERMINATE) + 1;

	DEBUG(3, ("SMBsendstrt (from %s to %s)\n",
		  xconn->smb1.msg_state->from,
		  xconn->smb1.msg_state->to));

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsendstrt);
	return;
}

/****************************************************************************
 Reply to a sendtxt.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_sendtxt(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *xconn = req->xconn;
	int len;
	const char *msg;
	char *tmp;
	size_t old_len;

	START_PROFILE(SMBsendtxt);

	if (! (*lp_message_command(talloc_tos(), lp_sub))) {
		reply_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		END_PROFILE(SMBsendtxt);
		return;
	}

	if ((xconn->smb1.msg_state == NULL) || (req->buflen < 3)) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsendtxt);
		return;
	}

	msg = (const char *)req->buf + 1;

	old_len = talloc_get_size(xconn->smb1.msg_state->msg);

	len = MIN(SVAL(msg, 0), smbreq_bufrem(req, msg+2));

	tmp = talloc_realloc(xconn->smb1.msg_state,
			     xconn->smb1.msg_state->msg,
			     char, old_len + len);

	if (tmp == NULL) {
		reply_nterror(req, NT_STATUS_NO_MEMORY);
		END_PROFILE(SMBsendtxt);
		return;
	}

	xconn->smb1.msg_state->msg = tmp;

	memcpy(&xconn->smb1.msg_state->msg[old_len], msg+2, len);

	DEBUG( 3, ( "SMBsendtxt\n" ) );

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsendtxt);
	return;
}

/****************************************************************************
 Reply to a sendend.
 conn POINTER CAN BE NULL HERE !
****************************************************************************/

void reply_sendend(struct smb_request *req)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *xconn = req->xconn;
	START_PROFILE(SMBsendend);

	if (! (*lp_message_command(talloc_tos(), lp_sub))) {
		reply_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
		END_PROFILE(SMBsendend);
		return;
	}

	if (xconn->smb1.msg_state == NULL) {
		reply_nterror(req, NT_STATUS_INVALID_PARAMETER);
		END_PROFILE(SMBsendend);
		return;
	}

	DEBUG(3,("SMBsendend\n"));

	msg_deliver(xconn->smb1.msg_state);

	TALLOC_FREE(xconn->smb1.msg_state);

	reply_smb1_outbuf(req, 0, 0);

	END_PROFILE(SMBsendend);
	return;
}
