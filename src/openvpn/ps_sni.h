/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef PS_SNI_H
#define PS_SNI_H

#if SNI_PASSTHROUGH

#include "socket.h"

/*
 * Client side: build and send an SNI routing header ClientHello
 * on the given connected TCP socket before the OpenVPN stream begins.
 * Returns true on success, false on failure.
 */
bool sni_passthrough_send_client_hello(socket_descriptor_t sd, const char *sni);

/*
 * Server side: drive the state machine that detects and discards the SNI
 * routing header prepended by --sni-passthrough-hostname clients.
 *
 * Returns true  — header consumed (or not present); caller continues normally.
 * Returns false — need more data, or a fatal error (sb->error set).
 */
bool sni_passthrough_check_and_consume_header(struct stream_buf *sb);


#endif /* SNI_PASSTHROUGH */

#endif /* PS_SNI_H */
