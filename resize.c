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

#if STDC_HEADERS
# include <stdio.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_CURSES_H
# include <curses.h>
#endif
#if HAVE_SIGNAL_H
# include <signal.h>
#endif
#if HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#if HAVE_TERMIOS_H
# include <termios.h>
#endif
#if HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#include "compat.h"

static RETSIGTYPE sigwinch();

static volatile int *flagp = NULL;

/* Set the flag when the window size changes */
static RETSIGTYPE
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
#ifndef SIGWINCH
	if (signal(SIGWINCH, sigwinch) == SIG_ERR)
		err(1, "signal");
#endif
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
