/* lckdir.c
   Get the name of the UUCP lock directory.

   Copyright (C) 1992 Ian Lance Taylor

   This file is part of the Taylor UUCP uuconf library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License
   as published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.

   The author of the program may be contacted at ian@airs.com.
   */

#include "uucnfi.h"

#if USE_RCS_ID
const char _uuconf_lckdir_rcsid[] = "$Id: lckdir.c,v 1.6 2002/03/05 19:10:42 ian Rel $";
#endif

/* Get the name of the UUCP lock directory.  */

int
uuconf_lockdir (pglobal, pzlock)
     pointer pglobal;
     const char **pzlock;
{
  struct sglobal *qglobal = (struct sglobal *) pglobal;

  *pzlock = qglobal->qprocess->zlockdir;
  return UUCONF_SUCCESS;
}
