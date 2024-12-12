/*
 * uucpd.c	Designed to be run from inetd. Checks loginname/password,
 *		also checks if this _really_ is a uucp login.
 *		Does utmp/wtmp accounting.
 *
 * Version:	@(#)uucpd.c  1.00  19-May-1998  miquels@cistron.nl
 * Version:	@(#)uucpd.c  1.10  28-Jul-2001  alex@king.net.nz
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <utmp.h>
#include <time.h>

#include <pwd.h>
#include <grp.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int myconv(int n,const struct pam_message **msg, struct pam_response **resp, void *ap)
{
	int k,rv;
	char *cp;

	rv=misc_conv(n,msg,resp,ap);
	if (rv != PAM_SUCCESS)
		return rv;
	/* 
	 * The supplied misc_conv function doesn't seem to strip the
	 * trailing return character so I do it here...
	 */
	for (k=0;k<n;k++)
		for (cp=((*resp)->resp);*cp!=0;cp++)
			if (*cp=='\r') *cp=0;
	return PAM_SUCCESS;
}

static struct pam_conv conv = {
	myconv,
	NULL
};

void chop(char *s)
{
	char *p;

	for(p = s; *p; p++)
		if (*p == '\r' || *p == '\n') {
			*p = 0;
			break;
		}
}


/*
 *	Read one line from the input.
 */
int getstr(int fd, char *buf, int len)
{
	int i, n, cnt;
	int nlseen = 0;

	cnt = 0;

	while(!nlseen) {
		if ((n = read(fd, buf + cnt, len - cnt)) <= 0) {
			if (n == -1 && errno == EINTR)
				continue;
			break;
		}
		cnt += n;
		for(i = 0; i < cnt; i++) {
			if (buf[i] == '\r' || buf[i] == '\n') {
				nlseen = 1;
				break;
			}
		}
		if (cnt >= len) break;
	}

	return cnt > 0 ? cnt : n;
}


int main(void)
{
	char login[UT_NAMESIZE];
	char host[UT_HOSTSIZE];
	struct passwd *pwd;
	char *s;
	struct sockaddr_in sin;
	int sinlen;
	struct hostent *h;
	struct utmp ut;
	pid_t pid;
	int st;
	int rv;
	pam_handle_t *pamh=NULL;

	/*
	 *	Make sure we have fds 0, 1 and 2.
	 */
	close(1);
	close(2);
	dup(0);
	dup(0);
	openlog("uucpd", LOG_PID, LOG_UUCP);

	/*
	 *	Get the remote host address.
	 */
	sinlen = sizeof(sin);
	if (getpeername(0, (struct sockaddr *)&sin, &sinlen) < 0) {
		syslog(LOG_ERR, "getpeername: %m");
		exit(1);
	}
	if ((h = gethostbyaddr((char *)&sin.sin_addr,
	    sizeof(sin.sin_addr), AF_INET)) != NULL) {
		strncpy(host, h->h_name, sizeof(host));
		host[sizeof(host) - 1] = 0;
	} else
		strcpy(host, inet_ntoa(sin.sin_addr));

	login[0] = 0;

	alarm(60);

	while(1) {
		printf("login: ");
		fflush(stdout);
		if (getstr(0, login, sizeof(login)) < 0)
			exit(1);
		login[sizeof(login) - 1] = 0;
		chop(login);
		if (login[0] != 0) break;
	}

	rv=pam_start("uucp",login,&conv,&pamh);
	if (rv==PAM_SUCCESS)
		rv=pam_authenticate(pamh, 0);
	if (rv==PAM_SUCCESS)
		rv=pam_set_item(pamh,PAM_RHOST,host);
	if (rv==PAM_SUCCESS) 
		rv=pam_acct_mgmt(pamh,0);
	if (rv!=PAM_SUCCESS) {
		syslog(LOG_AUTHPRIV|LOG_NOTICE,"%s",pam_strerror(pamh,rv));
		goto incorrect;
	}
	if ((pwd = getpwnam(login)) == NULL) {
incorrect:
		syslog(LOG_AUTHPRIV|LOG_NOTICE,
			"invalid password for `%s' on `TCP' from `%s'",
			login, host);
		printf("Login incorrect.\r\n");
		exit(1);
	}

	/*
	 *	See if we have a valid shell: the basename must
	 *	match uucico*
	 *
	 *	Note: arguably this check should be done by PAM, but
	 *	an appropriate PAM module doesn't exist to my knowledge.
	 */
	if ((s = strrchr(pwd->pw_shell, '/')) == NULL)
		s = pwd->pw_shell;
	else
		s++;
	if (strncmp(s, "uucico", 6) != 0) {
		syslog(LOG_AUTHPRIV|LOG_NOTICE,
			"invalid shell for `%s' on `TCP' from `%s'",
			login, host);
		printf("Invalid shell (not uucico)\r\n");
		exit(1);
	}

	/*
	 *	Allright we can assume the rest will go OK.
	 */
	memset(&ut, 0, sizeof(ut));
	ut.ut_type = LOGIN_PROCESS;
	strncpy(ut.ut_user, login, sizeof(ut.ut_user));
	strncpy(ut.ut_host, host, sizeof(ut.ut_host));
	ut.ut_addr = sin.sin_addr.s_addr;
	ut.ut_time = time(NULL);

	/*
	 *	Fork, let the parent wait to write the utmp file.
	 */
	signal(SIGHUP, SIG_IGN);
	if ((pid = fork()) != 0) {

		if (pid < 0) {
			/* FIXME: SCREAM (oh well..) */
			return 1;
		}
		pam_open_session(pamh, 0);

		ut.ut_pid = pid;
		sprintf(ut.ut_line, "uucp%d", ut.ut_pid);
		snprintf(ut.ut_id, sizeof(ut.ut_id), "uu%02x", ut.ut_pid&0xff);
		pututline(&ut);
		endutent();
		updwtmp(WTMP_FILE, &ut);

		while(wait(&st) != pid);
			;

		ut.ut_type = DEAD_PROCESS;
		ut.ut_time = time(NULL);
		ut.ut_user[0] = 0;
		pututline(&ut);
		endutent();
		updwtmp(WTMP_FILE, &ut);
		pam_close_session(pamh, 0);
		pam_end(pamh,PAM_SUCCESS);

		return 0;
	}

	/*
	 *	This is the child - exec uucico.
	 */
	signal(SIGHUP, SIG_DFL);
	if (chdir(pwd->pw_dir) != 0) {
		perror(pwd->pw_dir);
		exit(1);
	}
	if (setgid(pwd->pw_gid) != 0) {
		perror("setgid");
		exit(1);
	}
	if (initgroups(pwd->pw_name, pwd->pw_gid) < 0) {
		perror("initgroups");
		exit(1);
	}
	if (setuid(pwd->pw_uid) != 0) {
		perror("setuid");
		exit(1);
	}
	setenv("LOGNAME", pwd->pw_name, 1);
	setenv("USER", pwd->pw_name, 1);
	setenv("SHELL", pwd->pw_shell, 1);
	setenv("TERM", "dumb", 1);


	execl(pwd->pw_shell, pwd->pw_shell, NULL);

	perror(pwd->pw_shell);
	return 1;
}

