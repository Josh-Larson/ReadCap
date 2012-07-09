/**
 * *********************************************************************
 * OpenSWG Sandbox Server
 * Copyright (C) 2006 OpenSWG Team <http://www.openswg.com>
 * *********************************************************************
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * To read the license please visit http://www.gnu.org/copyleft/gpl.html
 * *********************************************************************
 */

#ifndef OPENSWG_COMMON_H
#define OPENSWG_COMMON_H

#define OPENSWG_CONFIG "openswg.conf"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <signal.h>

#include <exception>
#include <set>
#include <list>
#include <string>
#include <map>
#include <queue>
#include <sstream>
#include <algorithm>

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <mmsystem.h>
# include <time.h>
#define I64FMTD "%I64u"
#else
#define I64FMTD "%llu"
# if defined(__FreeBSD__) || defined(__APPLE_CC__)
#   include <time.h>
# endif
#   include <sys/timeb.h>
#endif

#ifdef __GNUG__
__extension__
typedef unsigned long long  uint64;
#else
typedef unsigned long long  uint64;
#endif
typedef unsigned long       uint32;
typedef unsigned short      uint16;
typedef unsigned char       uint8;
typedef unsigned int        uint;
typedef unsigned short      unicode;
typedef int					int32;

extern bool running;

#endif // OPENSWG_COMMON_H
