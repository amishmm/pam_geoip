/*
 * pam_geoip.c - account module to check GeoIP information
 *
 * $Id$
 *
 */
/*
 * Copyright (c) 2010-2012 Hanno Hecker <vetinari@ankh-morp.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the
 * GPL are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "pam_geoip.h"

void
free_locations(struct locations *list) {
    struct locations *entry;
    while (list) {
        entry = list;
        list  = list->next;
        if (entry->city != NULL)
            free(entry->city);
        if (entry->country != NULL)
            free(entry->country);
        free(entry);
    }
}

void
free_opts(struct options *opts) {
    if (opts->system_file)
        free(opts->system_file);
    if (opts->service_file)
        free(opts->service_file);
    if (opts->geoip_db)
        free(opts->geoip_db);
#ifdef HAVE_GEOIP_010408
    if (opts->geoip6_db)
        free(opts->geoip6_db);
#endif
    free(opts);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh,
                int flags,
                int argc,
                const char **argv)
{
    struct options *opts;
    FILE *fh;
    char *username;        /* username requesting access */
    char *rhost;           /* remote host */
    char *srv;             /* PAM service we're running as */
    char buf[LINE_LENGTH];
    int retval, action;
    int is_v6 = 0;
    struct locations *geo;
    unsigned char gi_type;

    GeoIP       *gi   = NULL;
#ifdef HAVE_GEOIP_010408
    GeoIP       *gi6  = NULL;
    int is_city6_db   = 0;
#endif
    GeoIPRecord *rec  = NULL;

    opts = malloc(sizeof(struct options));
    if (opts == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts': %m");
        return PAM_SERVICE_ERR;
    }
    opts->charset      = GEOIP_CHARSET_UTF8;
    opts->debug        = 0;
    opts->action       = PAM_PERM_DENIED;
    opts->system_file  = NULL;
    opts->service_file = NULL;
    opts->by_service   = 0;
    opts->geoip_db     = NULL;
#ifdef HAVE_GEOIP_010408
    opts->use_v6       = 0;
    opts->v6_first     = 0;
    opts->geoip6_db    = NULL;
#endif
    opts->is_city_db   = 0;

    geo = malloc(sizeof(struct locations));
    if (geo == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'geo': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }
    geo->country = NULL;
    geo->city    = NULL;
    geo->next    = NULL;

    _parse_args(pamh, argc, argv, opts);

    if (opts->system_file == NULL)
        opts->system_file = strdup(SYSTEM_FILE);
    if (opts->system_file == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->system_file': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }

    if (opts->geoip_db == NULL)
        opts->geoip_db = strdup(GEOIPDB_FILE);
    if (opts->geoip_db == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->geoip_db': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }

#ifdef HAVE_GEOIP_010408
    if (opts->geoip6_db == NULL)
        opts->geoip6_db = strdup(GEOIP6DB_FILE);
    if (opts->geoip6_db == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->geoip6_db': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }
#endif

    retval = pam_get_item(pamh, PAM_USER, (void*) &username);
    if (username == NULL || retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "error recovering username");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    retval = pam_get_item(pamh, PAM_RHOST, (void*) &rhost);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "error fetching rhost");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    if (rhost == NULL) {
        pam_syslog(pamh, LOG_INFO, "rhost is NULL, allowing");
        free_opts(opts);
        free_locations(geo);
        return PAM_SUCCESS;
    }

    retval = pam_get_item(pamh, PAM_SERVICE, (void*) &srv);
    if (srv == NULL || retval != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_CRIT, "error requesting service name");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    opts->service_file = malloc(PATH_MAX);
    if (opts->service_file == NULL) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'service_file': %m");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    if (snprintf(opts->service_file, PATH_MAX-1, SERVICE_FILE, srv) < 0) {
        pam_syslog(pamh, LOG_CRIT, "snprintf error 'service_file'");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    gi = GeoIP_open(opts->geoip_db, GEOIP_INDEX_CACHE);
    if (gi == NULL) {
        pam_syslog(pamh, LOG_CRIT,
                        "failed to open geoip db (%s): %m", opts->geoip_db);
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    gi_type = GeoIP_database_edition(gi);
    if (opts->debug)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP edition: %d", gi_type);
    switch (gi_type) {
        case GEOIP_COUNTRY_EDITION:
            if (opts->debug)
                pam_syslog(pamh, LOG_DEBUG, "GeoIP v4 edition: country");
            opts->is_city_db = 0;
            break;
        case GEOIP_CITY_EDITION_REV0:
            if (opts->debug)
                pam_syslog(pamh, LOG_DEBUG, "GeoIP v4 edition: city rev0");
            opts->is_city_db = 1;
            break;
        case GEOIP_CITY_EDITION_REV1:
            if (opts->debug)
                pam_syslog(pamh, LOG_DEBUG, "GeoIP v4 edition: city rev1");
            opts->is_city_db = 1;
            break;
        default:
            pam_syslog(pamh, LOG_CRIT, "invalid GeoIP DB type `%d' found", gi_type);
            GeoIP_delete(gi);
            free_opts(opts);
            free_locations(geo);
            return PAM_SERVICE_ERR;
    }
    GeoIP_set_charset(gi, opts->charset);
    if (opts->debug)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP DB is City: %s",
                                        opts->is_city_db ? "yes" : "no");

#ifdef HAVE_GEOIP_010408
    if (opts->use_v6 != 0) {
        gi6 = GeoIP_open(opts->geoip6_db, GEOIP_INDEX_CACHE);
        if (gi6 == NULL) {
            pam_syslog(pamh, LOG_CRIT,
                            "failed to open geoip6 db (%s): %m", opts->geoip6_db);
            GeoIP_delete(gi);
            free_opts(opts);
            free_locations(geo);
            return PAM_SERVICE_ERR;
        }
        gi_type = GeoIP_database_edition(gi6);

        switch (gi_type) {
            case GEOIP_COUNTRY_EDITION_V6:
                if (opts->debug)
                    pam_syslog(pamh, LOG_DEBUG, "GeoIP v6 edition: country");
                is_city6_db = 0;
                break;
            case GEOIP_CITY_EDITION_REV0_V6:
                if (opts->debug)
                    pam_syslog(pamh, LOG_DEBUG, "GeoIP v6 edition: city rev0");
                is_city6_db = 1;
                break;
            case GEOIP_CITY_EDITION_REV1_V6:
                if (opts->debug)
                    pam_syslog(pamh, LOG_DEBUG, "GeoIP v6 edition: city rev1");
                is_city6_db = 1;
                break;
            default:
                pam_syslog(pamh, LOG_CRIT, "invalid GeoIP DB type `%d' found", gi_type);
                GeoIP_delete(gi);
                GeoIP_delete(gi6);
                free_opts(opts);
                free_locations(geo);
                return PAM_SERVICE_ERR;
        }
        if (opts->debug)
            pam_syslog(pamh, LOG_DEBUG, "GeoIP DB is City v6: %s",
                is_city6_db ? "yes" : "no");
        GeoIP_set_charset(gi6, opts->charset);

        if (opts->is_city_db != is_city6_db) {
            pam_syslog(pamh, LOG_CRIT, "IPv4 DB type is not the same as IPv6 (not both Country edition or both City edition)");
            GeoIP_delete(gi);
            GeoIP_delete(gi6);
            free_opts(opts);
            free_locations(geo);
            return PAM_SERVICE_ERR;
        }

        if (opts->v6_first != 0) {
            rec = GeoIP_record_by_name_v6(gi6, rhost);
            if (rec == NULL) {
                if (opts->debug)
                    pam_syslog(pamh, LOG_DEBUG, "no IPv6 record for %s, trying IPv4", rhost);
                rec = GeoIP_record_by_name(gi, rhost);
            }
            else
                is_v6 = 1;
        }
        else {
            rec = GeoIP_record_by_name(gi, rhost);
            if (rec == NULL) {
                if (opts->debug)
                    pam_syslog(pamh, LOG_DEBUG, "no IPv4 record for %s, trying IPv6", rhost);
                rec = GeoIP_record_by_name_v6(gi6, rhost);
                if (rec != NULL)
                    is_v6 = 1;
            }
        }
    }
    else
#endif /* HAVE_GEOIP_010408 */
        rec = GeoIP_record_by_name(gi, rhost);

    if (rec == NULL) {
        pam_syslog(pamh, LOG_INFO, "no record for %s, setting GeoIP to 'UNKNOWN,*'", rhost);

        geo->city    = strdup("*");
        geo->country = strdup("UNKNOWN");

        if (geo->city == NULL || geo->country == NULL) {
            pam_syslog(pamh, LOG_CRIT, "malloc error 'geo->{city,country}': %m");
            GeoIP_delete(gi);
#ifdef HAVE_GEOIP_010408
            GeoIP_delete(gi6);
#endif
            free_opts(opts);
            free_locations(geo);
            return PAM_SERVICE_ERR;
        }
    }
    else {
        if (rec->city == NULL || opts->is_city_db == 0)
            geo->city = strdup("*");
        else
            geo->city = strdup(rec->city);

        if (rec->country_code == NULL)
            geo->country = strdup("UNKNOWN");
        else
            geo->country = strdup(rec->country_code);

        if (geo->city == NULL || geo->country == NULL) {
            pam_syslog(pamh, LOG_CRIT, "malloc error 'geo->{city,country}': %m");
            GeoIP_delete(gi);
#ifdef HAVE_GEOIP_010408
            GeoIP_delete(gi6);
#endif
            free_opts(opts);
            free_locations(geo);
            return PAM_SERVICE_ERR;
        }

        if (opts->is_city_db) {
            geo->latitude  = rec->latitude;
            geo->longitude = rec->longitude;
        }
    }

    if (opts->debug)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP record for %s: %s,%s",
                                rhost, geo->country, geo->city);

    if (opts->debug && strcmp(geo->country, "UNKNOWN") != 0 && opts->is_city_db)
        pam_syslog(pamh, LOG_DEBUG, "GeoIP coordinates for %s: %f,%f",
                                    rhost, geo->latitude, geo->longitude);

    if ((fh = fopen(opts->service_file, "r")) != NULL) {
        opts->by_service = 1;
        if (opts->debug)
            pam_syslog(pamh, LOG_DEBUG, "using services file %s",
                                        opts->service_file);
    }
    else {
        if ((fh = fopen(opts->system_file, "r")) == NULL) {
            pam_syslog(pamh, LOG_CRIT, "error opening %s: %m", opts->system_file);

#ifdef HAVE_GEOIP_010408
            if (gi6) GeoIP_delete(gi6);
#endif
            if (gi) GeoIP_delete(gi);
            if (rec) GeoIPRecord_delete(rec);
            free_opts(opts);
            return PAM_SERVICE_ERR;
        }
    }

    action = opts->action;
    char location[LINE_LENGTH];
    while (fgets(buf, LINE_LENGTH, fh) != NULL) {
        char *line, *ptr;
        char domain[LINE_LENGTH],
             service[LINE_LENGTH];

        action = opts->action;
        line   = buf;
        /* skip the leading white space */
        while (*line && isspace(*line))
            line++;

        /* Rip off the comments */
        ptr = strchr(line,'#');
        if (ptr)
            *ptr = '\0';
        /* Rip off the newline char */
        ptr = strchr(line,'\n');
        if (ptr)
            *ptr = '\0';
        /* Anything left ? */
        if (!strlen(line))
            continue;

        if (opts->by_service)
            action = parse_line_srv(pamh, line, domain, location);
        else
            action = parse_line_sys(pamh, line, domain, service, location);
        if (action < 0) { /* parsing failed */
            action = opts->action;
            continue;
        }

        if (!opts->by_service) {
            if (!check_service(pamh, service, srv))
                continue;
        }

        if ((strcmp(domain, "*") == 0) || (strcmp(username, domain) == 0)) {
            if (check_location(pamh, opts, location, geo))
                break;
        }
        else if (domain[0] == '@') {
            if (pam_modutil_user_in_group_nam_nam(pamh, username, domain+1)) {
                if (check_location(pamh, opts, location, geo))
                    break;
            }
        }
    }

    fclose(fh);
    if (gi) GeoIP_delete(gi);
#ifdef HAVE_GEOIP_010408
    if (gi6) GeoIP_delete(gi6);
#endif
    if (rec) GeoIPRecord_delete(rec);
    free_locations(geo);

    switch (action) {
        case PAM_SUCCESS:
            pam_syslog(pamh, LOG_DEBUG, "location %s allowed for user %s from %s (IPv%d)", location, username, rhost, is_v6 ? 6 : 4);
            break;
        case PAM_PERM_DENIED:
            pam_syslog(pamh, LOG_DEBUG, "location %s denied for user %s from %s (IPv%d)", location, username, rhost, is_v6 ? 6 : 4);
            break;
        case PAM_IGNORE:
            pam_syslog(pamh, LOG_DEBUG, "location %s ignored for user %s from %s (IPv%d)", location, username, rhost, is_v6 ? 6 : 4);
            break;
        default: /* should not happen */
            pam_syslog(pamh, LOG_DEBUG, "location status: %d, IPv%d", action, is_v6 ? 6 : 4);
            break;
    };
    free_opts(opts);
    return action;
}
/*
 * vim: ts=4 sw=4 expandtab
 */
