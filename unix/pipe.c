/* pipe.c
   The pipe port communication routines for Unix.
   Contributed by Marc Boucher <marc@CAM.ORG>.

   Copyright (C) 1993, 2002 Ian Lance Taylor

   This file is part of the Taylor UUCP package.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.

   The author of the program may be contacted at ian@airs.com.
   */

#include "uucp.h"

#if USE_RCS_ID
const char pipe_rcsid[] = "$Id: pipe.c,v 1.10 2002/03/05 19:10:42 ian Rel $";
#endif

#include "uudefs.h"
#include "uuconf.h"
#include "system.h"
#include "conn.h"
#include "sysdep.h"

#include <errno.h>

/* needed for waitpid (XXX might be done with #if) */
#include <sys/types.h>
#include <sys/wait.h>

#if HAVE_FCNTL_H
#include <fcntl.h>
#else
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#endif

/* Local functions.  */

static void uspipe_free P((struct sconnection *qconn));
static boolean fspipe_open P((struct sconnection *qconn, long ibaud,
			      boolean fwait, boolean fuser, boolean nortscts));
static boolean fspipe_close P((struct sconnection *qconn,
			       pointer puuconf,
			       struct uuconf_dialer *qdialer,
			       boolean fsuccess));
static boolean fspipe_dial P((struct sconnection *qconn, pointer puuconf,
			      const struct uuconf_system *qsys,
			      const char *zphone,
			      struct uuconf_dialer *qdialer,
			      enum tdialerfound *ptdialer));

/* The command table for standard input ports.  */

static const struct sconncmds spipecmds =
{
  uspipe_free,
  NULL, /* pflock */
  NULL, /* pfunlock */
  fspipe_open,
  fspipe_close,
  fspipe_dial,
  fsdouble_read,
  fsdouble_write,
  fsysdep_conn_io,
  NULL, /* pfbreak */
  NULL, /* pfset */
  NULL, /* pfcarrier */
  fsdouble_chat,
  NULL  /* pibaud */
};

/* Initialize a pipe connection.  */

boolean
fsysdep_pipe_init (qconn)
     struct sconnection *qconn;
{
  struct ssysdep_conn *q;

  q = (struct ssysdep_conn *) xmalloc (sizeof (struct ssysdep_conn));
  q->o = -1;
  q->ord = -1;
  q->owr = -1;
  q->zdevice = NULL;
  q->iflags = -1;
  q->iwr_flags = -1;
  q->fterminal = FALSE;
  q->ftli = FALSE;
  q->ibaud = 0;
  q->ipid = -1;
  qconn->psysdep = (pointer) q;
  qconn->qcmds = &spipecmds;
  return TRUE;
}

static void
uspipe_free (qconn)
     struct sconnection *qconn;
{
  xfree (qconn->psysdep);
}

/* Open a pipe port.  */

/*ARGSUSED*/
static boolean
fspipe_open (qconn, ibaud, fwait, fuser, nortscts)
     struct sconnection *qconn ATTRIBUTE_UNUSED;
     long ibaud ATTRIBUTE_UNUSED;
     boolean fwait;
     boolean fuser ATTRIBUTE_UNUSED;
     boolean nortscts ATTRIBUTE_UNUSED;
{
  /* We don't do incoming waits on pipes.  */
  if (fwait)
    return FALSE;

  return TRUE;
}

/* Close a pipe port.  */

/*ARGSUSED*/
static boolean
fspipe_close (qconn, puuconf, qdialer, fsuccess)
     struct sconnection *qconn;
     pointer puuconf ATTRIBUTE_UNUSED;
     struct uuconf_dialer *qdialer ATTRIBUTE_UNUSED;
     boolean fsuccess ATTRIBUTE_UNUSED;
{
  struct ssysdep_conn *qsysdep;
  boolean fret;

  qsysdep = (struct ssysdep_conn *) qconn->psysdep;
  fret = TRUE;

  /* Close our sides of the pipe.  */
  if (qsysdep->ord >= 0 && close (qsysdep->ord) < 0)
    {
      ulog (LOG_ERROR, "fspipe_close: close read fd: %s", strerror (errno));
      fret = FALSE;
    }
  if (qsysdep->owr != qsysdep->ord
      && qsysdep->owr >= 0
      && close (qsysdep->owr) < 0)
    {
      ulog (LOG_ERROR, "fspipe_close: close write fd: %s", strerror (errno));
      fret = FALSE;
    }
  qsysdep->ord = -1;
  qsysdep->owr = -1;

  /* Kill dangling child process.  */
  if (qsysdep->ipid >= 0)
    {
      if (kill (qsysdep->ipid, SIGHUP) == 0)
        {
          #if defined (HAVE_USLEEP) && defined (HAVE_WAITPID)
          /* Avoid wasting 4 seconds (including the SIGPIPE case below).
             Quick and dirty work-around to avoid depending on SIGCHLD:
             Just sleep up to 20 times 0.1s as long as the child exists. */
          int i, status;
          for (i = 20; i > 0; i--)
            {
              if (waitpid (qsysdep->ipid, &status, WNOHANG) == qsysdep->ipid)
                {
                  qsysdep->ipid = -1;
                  return fret;
                }
              usleep (100000);
            }
          #else
          usysdep_sleep (2);
          #endif
        }
#ifdef SIGPIPE
      if (kill (qsysdep->ipid, SIGPIPE) == 0)
        {
          #if HAVE_USLEEP
          int i, status;
          for (i = 20; i > 0; i--)
            {
              if (waitpid (qsysdep->ipid, &status, WNOHANG) == qsysdep->ipid)
                {
                  qsysdep->ipid = -1;
                  return fret;
                }
              usleep (100000);
            }
          #else
          usysdep_sleep (2);
          #endif
        }
#endif
      if (kill (qsysdep->ipid, SIGKILL) < 0 && errno == EPERM)
	{
	  ulog (LOG_ERROR, "fspipe_close: Cannot kill child pid %lu: %s",
		(unsigned long) qsysdep->ipid, strerror (errno));
	  fret = FALSE;
	}
      else
	(void) ixswait ((unsigned long) qsysdep->ipid, (const char *) NULL);
    }
  qsysdep->ipid = -1;
  return fret;
}

/* Dial out on a pipe port, so to speak: launch connection program
   under us.  The code alternates q->o between q->ord and q->owr as
   appropriate.  It is always q->ord before any call to fsblock.  */

/*ARGSUSED*/
static boolean
fspipe_dial (qconn, puuconf, qsys, zphone, qdialer, ptdialer)
     struct sconnection *qconn;
     pointer puuconf;
     const struct uuconf_system *qsys;
     const char *zphone;
     struct uuconf_dialer *qdialer;
     enum tdialerfound *ptdialer;
{
  struct ssysdep_conn *q;
  int aidescs[3];
  //XXX const char **pzprog;
  char **pzprog;
  char **p;

  q = (struct ssysdep_conn *) qconn->psysdep;

  *ptdialer = DIALERFOUND_FALSE;

  //XXX pzprog = (const char **) qconn->qport->uuconf_u.uuconf_spipe.uuconf_pzcmd;
  pzprog = qconn->qport->uuconf_u.uuconf_spipe.uuconf_pzcmd;

  if (pzprog == NULL)
    {
      ulog (LOG_ERROR, "No command for pipe connection");
      return FALSE;
    }

  /* Look for a string \H and replace it by the address given for this system */
  for (p=pzprog; *p; p++)
    if (!strcmp(*p, "\\H"))
      *p = zphone;

  /* Look for a string \Z and replace by the system name to be called */
  for (p=pzprog; *p; p++)
    if (!strcmp(*p, "\\Z"))
      *p = qsys->uuconf_zname;

  aidescs[0] = SPAWN_WRITE_PIPE;
  aidescs[1] = SPAWN_READ_PIPE;
  aidescs[2] = SPAWN_NULL;

  /* Pass fkeepuid, fkeepenv and fshell as TRUE.  This puts the
     responsibility of security on the connection program.  */
  q->ipid = ixsspawn ((const char **)pzprog, aidescs, TRUE, TRUE, (const char *) NULL,
		      FALSE, TRUE, (const char *) NULL,
		      (const char *) NULL, (const char *) NULL);
  if (q->ipid < 0)
    {
      ulog (LOG_ERROR, "ixsspawn (%s): %s", pzprog[0], strerror (errno));
      return FALSE;
    }

  q->owr = aidescs[0];
  q->ord = aidescs[1];
  q->o = q->ord;

  q->iflags = fcntl (q->ord, F_GETFL, 0);
  q->iwr_flags = fcntl (q->owr, F_GETFL, 0);
  if (q->iflags < 0 || q->iwr_flags < 0)
    {
      ulog (LOG_ERROR, "fspipe_dial: fcntl: %s", strerror (errno));
      (void) fspipe_close (qconn, puuconf, qdialer, FALSE);
      return FALSE;
    }

  return TRUE;
}

#if 0

/* Marc Boucher's contributed code used an alarm to avoid waiting too
   long when closing the pipe.  However, I believe that it is not
   possible for the kernel to sleep when closing a pipe; it is only
   possible when closing a device.  Therefore, I have removed the
   code, but am preserving it in case I am wrong.  To reenable it, the
   two calls to close in fspipe_close should be changed to call
   fspipe_alarmclose.  */

static RETSIGTYPE
usalarm (isig)
     int isig;
{
#if ! HAVE_SIGACTION && ! HAVE_SIGVEC && ! HAVE_SIGSET
  (void) signal (isig, usalarm);
#endif

#if HAVE_RESTARTABLE_SYSCALLS
  longjmp (sSjmp_buf, 1);
#endif
}

static int
fspipe_alarmclose (fd)
     int fd;
{
  int iret = -1;
  int ierrno = 0;

  if (fsysdep_catch ())
    {
      usysdep_start_catch ();
      usset_signal (SIGALRM, usalarm, TRUE, (boolean *) NULL);
      (void) alarm (30);

      iret = close (fd);
      ierrno = errno;
    }

  usset_signal (SIGALRM, SIG_IGN, TRUE, (boolean *) NULL);
  (void) alarm (0);
  usysdep_end_catch ();

  errno = ierrno;
  return iret;
}

#endif /* 0 */
