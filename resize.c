/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <curses.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <err.h>

static volatile int * flagp = NULL;

static void
sigwinch(sig)
	int sig;
{
	if (flagp)
		*flagp = 1;
}

void
resize_init(fp)
	volatile int *fp;
{
	flagp = fp;
	*flagp = 0;
	if (signal(SIGWINCH, sigwinch) == SIG_ERR)
		err(1, "signal");
}

void
resize()
{
	struct winsize ws;

	*flagp = 0;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1)
		err(1, "TIOCGWINSZ");
	resizeterm(ws.ws_row, ws.ws_col);
}
