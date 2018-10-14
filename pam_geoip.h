/*
 * pam_geoip.h - account module to check GeoIP information
 *
 * $Id$
 *
 */

#ifndef _PAM_GEOIP_H
#define _PAM_GEOIP_H

#define _GNU_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include <GeoIP.h>
#include <GeoIPCity.h>

#include "config.h"

#define LINE_LENGTH 4095

#define MASK_NO_MASK  -1
#define MASK_TOO_LONG -2
#define MASK_NOT_NUM  -3
#define MASK_TOO_BIG  -4

#include <security/pam_modutil.h> /* pam_modutil_user_in_group_nam_nam() */
#include <security/pam_ext.h>     /* pam_syslog() */
#include <security/pam_appl.h>
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>

#ifndef PATH_MAX
# define PATH_MAX 1024
#endif /* PATH_MAX */

#define SYSTEM_FILE  "/etc/security/geoip.conf"
#define SERVICE_FILE "/etc/security/geoip.%s.conf"
#define GEOIPDB_FILE "/usr/local/share/GeoIP/GeoIPCity.dat"

#ifdef HAVE_GEOIP_010408
#define GEOIP6DB_FILE "/usr/local/share/GeoIP/GeoIPCityv6.dat"
#endif

/* GeoIP locations in geoip.conf */
struct locations {
    char *country;
    char *city;
    float latitude;
    float longitude;
    float radius;     /* in km */
    struct locations *next;
};

/* options set on "command line" in /etc/pam.d/ */
struct options {
    char *system_file;
    char *geoip_db;
#ifdef HAVE_GEOIP_010408
    char *geoip6_db;
#endif
    char *service_file; /* not on cmd line */
    int  by_service;    /* if service_file can be opened this is true */
    int  charset;
    int  action;
#ifdef HAVE_GEOIP_010408
    int  use_v6;
    int  v6_first;
#endif
    int  is_city_db;
    int  debug;
};

extern struct locations *
parse_locations(pam_handle_t *pamh,
                struct options *opts,
                char *location_string);


extern void
free_locations(struct locations *list);

extern void
free_opts(struct options *opts);

extern int
parse_action(pam_handle_t *pamh, char *name);

extern int
parse_line_srv(pam_handle_t *pamh,
           char *line,
           char *domain,
           char *location);


extern int
parse_line_sys(pam_handle_t *pamh,
           char *line,
           char *domain,
           char *service,
           char *location);

extern int
check_service(pam_handle_t *pamh, char *services, char *srv);

extern double
calc_distance(float latitude, float longitude, float geo_lat, float geo_long);


extern int
check_location(pam_handle_t *pamh,
               struct options *opts,
               char *location_string,
               struct locations *geo);

extern void
_parse_args(pam_handle_t *pamh,
             int argc,
             const char **argv,
             struct options *opts);

#endif /* _PAM_GEOIP_H */
/*
 * vim: ts=4 sw=4 expandtab
 */
