/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * This compilation unit provides a callback mechanism for display.c
 * to tell it if the display needs resizing. It is separated
 * here in case system-independent window resizing becomes complicated.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <curses.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <err.h>

static void sigwinch(int sig);

static volatile int *flagp = NULL;

/* Set the flag when the window size changes */
static void
sigwinch(sig)
	int sig;
{
	if (flagp)
		*flagp = 1;
}

/* Install a signal handler that sets a given flag when the window resizes */
void
resize_init(fp)
	volatile int *fp;
{
	flagp = fp;
	*flagp = 0;
	if (signal(SIGWINCH, sigwinch) == SIG_ERR)
		err(1, "signal");
}

/* This should be called when the flag has been set by the sigwinch handler */
void
resize()
{
	struct winsize ws;

	*flagp = 0;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1)
		err(1, "TIOCGWINSZ");
	resizeterm(ws.ws_row, ws.ws_col);
}
