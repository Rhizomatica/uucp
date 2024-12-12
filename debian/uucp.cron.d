#
# Every hour start the uudemon.hr. To actually poll a remote system,
# enter its name in /etc/uucp/Poll. You are encouraged to change the "8".
#
8 * * * *      uucp    [ -x /usr/lib/uucp/uudemon.hr ] && /usr/lib/uucp/uudemon.hr
#
# Alternative to adding a system to the (non-standard) /etc/uucp/Poll file:
# just call uucico here to poll the system directly from cron.
#
# min   hour    dom     month   dow     user    command
#12     *       *       *       *       uucp    /usr/sbin/uucico -r1 -x3 -f -s<system>

