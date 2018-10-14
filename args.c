/*
 * args.c - account module to check GeoIP information
 *
 * $Id$
 *
 */

#include "pam_geoip.h"

void _parse_args(pam_handle_t *pamh,
                 int argc,
                 const char **argv,
                 struct options *opts)
{
    int i = 0;

    for (i=0; i<argc; i++) {
        if (strncmp(argv[i], "system_file=", 12) == 0) {
            if (argv[i]+12 != '\0')
                opts->system_file = strndup(argv[i]+12, PATH_MAX);
        }
        else if (strncmp(argv[i], "geoip_db=", 9) == 0) {
            if (argv[i]+9 != '\0')
                opts->geoip_db = strndup(argv[i]+9, PATH_MAX);
        }
#ifdef HAVE_GEOIP_010408
        else if (strncmp(argv[i], "v6_first=", 9) == 0) {
            if (argv[i]+9 != '\0')
                opts->v6_first = atoi(argv[i]+9);
        }
        else if (strncmp(argv[i], "use_v6=", 7) == 0) {
            if (argv[i]+7 != '\0')
                opts->use_v6 = atoi(argv[i]+7);
        }
        else if (strncmp(argv[i], "geoip6_db=", 10) == 0) {
            if (argv[i]+10 != '\0')
                opts->geoip6_db = strndup(argv[i]+10, PATH_MAX);
        }
#endif
        else if (strncmp(argv[i], "charset=", 8) == 0) {
            if (argv[i]+8 != '\0') {
                if (strncasecmp(argv[i]+8, "UTF-8", 5) == 0) {
                    opts->charset = GEOIP_CHARSET_UTF8;
                }
                else if (strncasecmp(argv[i]+8, "UTF8", 4) == 0) {
                    opts->charset = GEOIP_CHARSET_UTF8;
                }
                else if (strncasecmp(argv[i]+8, "iso-8859-1", 10) == 0) {
                    opts->charset = GEOIP_CHARSET_ISO_8859_1;
                }
            }
        }
        else if (strncmp(argv[i], "debug", 5) == 0) {
            opts->debug = 1;
        }
        else if (strncmp(argv[i], "action=", 7) == 0) {
            if (argv[i]+7 != '\0') {
                if (strncmp(argv[i]+7, "allow", 5) == 0) {
                    opts->action = PAM_SUCCESS;
                }
                else if (strncmp(argv[i]+7, "deny", 4) == 0) {
                    opts->action = PAM_PERM_DENIED;
                }
                else if (strncmp(argv[i]+7, "ignore", 6) == 0) {
                    opts->action = PAM_IGNORE;
                }
            }
        }
        else {
            pam_syslog(pamh, LOG_WARNING, "unknown parameter %s", argv[i]);
        }
    }
}
/*
 * vim: ts=4 sw=4 expandtab
 */
