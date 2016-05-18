/**
* Copyright 2017 The Open Source Research Group,
*                University of Erlangen-Nürnberg
*
* Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     https://www.gnu.org/licenses/gpl.html
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __DOIP_PAYLOAD_HANDLER_H
#define __DOIP_PAYLOAD_HANDLER_H

#include "config.h"
#include <epan/packet.h>

#include "doip-header.h"

/* payload_handler is a function pointer to
 * a function which can further dissect a package
 */
typedef
void (*payload_handler)(doip_header *, packet_info *, proto_tree *);

/* Determines a suitable payload_handler based on 
 * a header's payload type
 *
 * @param[in] header, header containing payload type
 * @return a valid payload_handler if payload type can be handled,
 *  otherwise NULL
 */
payload_handler
find_matching_payload_handler(doip_header *);


#endif /* __DOIP_PAYLOAD_HANDLER_H */


