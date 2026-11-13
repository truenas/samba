/*
 *  Unix SMB/CIFS implementation.
 *  Keep Kerberos sessions valid after the end time of the ticket
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SMBD_TRUENAS_SESSION_REVALIDATE_H__
#define __SMBD_TRUENAS_SESSION_REVALIDATE_H__

struct smbXsrv_session;

/*
 * Call this function after a session setup sets the expiration time of
 * the session. See truenas_session_revalidate.c.
 */
void truenas_session_revalidate_setup(struct smbXsrv_session *session);

#endif /* __SMBD_TRUENAS_SESSION_REVALIDATE_H__ */
