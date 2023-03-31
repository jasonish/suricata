/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef SC_CONFIG_H
#define SC_CONFIG_H

#include "suricata-common.h"
#include "conf.h"

#include "rust-config.h"

void SCConfigFree(void);
void SCConfigBackup(void);
void SCConfigRestore(void);
SCConfigValue *SCConfigGetRoot(void);
void SCConfigSetRoot(SCConfigValue *config);
void SCConfigValueToLegacy(ConfNode *parent, SCConfigValue *value);
bool SCConfigLoad(const char *filename);

#endif /* SC_CONFIG_H */
