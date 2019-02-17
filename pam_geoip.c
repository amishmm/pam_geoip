/*
 * pam_geoip.c - account module to check GeoIP information
 *
 * $Id$
 *
 */
/*
 * Copyright (c) 2019 Amish - GeoIP2 support
 * Copyright (c) 2010-2012 Hanno Hecker - Legacy GeoIP <vetinari@ankh-morp.org>
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

void free_locations(struct locations *list)
{
    struct locations *entry;
    while (list) {
        entry = list;
        list  = list->next;
        if (entry->city) free(entry->city);
        if (entry->country) free(entry->country);
        free(entry);
    }
}


void free_opts(struct options *opts)
{
    if (opts->system_file) free(opts->system_file);
    if (opts->service_file) free(opts->service_file);
    if (opts->geoip_db) free(opts->geoip_db);
    if (opts->language) free(opts->language);
    free(opts);
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct options *opts;
    FILE *fh;
    char *username;        /* username requesting access */
    char *rhost;           /* remote host */
    char *srv;             /* PAM service we're running as */
    char buf[LINE_LENGTH];
    int retval, action;
    struct locations *geo;
    const char *gi_type;

    MMDB_s gi;
    MMDB_lookup_result_s rec;
    MMDB_entry_data_s entry_data;
    int gai_error, mmdb_error;

    opts = malloc(sizeof(struct options));
    if (!opts) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts': %m");
        return PAM_SERVICE_ERR;
    }
    opts->debug = 0;
    opts->action = PAM_PERM_DENIED;
    opts->system_file = NULL;
    opts->service_file = NULL;
    opts->by_service = 0;
    opts->geoip_db = NULL;
    opts->is_city_db = 0;
    opts->language = NULL;

    geo = malloc(sizeof(struct locations));
    if (!geo) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'geo': %m");
        free_opts(opts);
        return PAM_SERVICE_ERR;
    }
    geo->country = NULL;
    geo->city = NULL;
    geo->next = NULL;
    geo->latitude = 90.0;
    geo->longitude = 0.0;

    _parse_args(pamh, argc, argv, opts);

    if (!opts->system_file) opts->system_file = strdup(SYSTEM_FILE);
    if (!opts->system_file) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->system_file': %m");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    if (!opts->geoip_db) opts->geoip_db = strdup(GEOIPDB_FILE);
    if (!opts->geoip_db) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->geoip_db': %m");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    if (!opts->language) opts->language = strdup("en");
    if (!opts->language) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'opts->language': %m");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }
    if (opts->debug) pam_syslog(pamh, LOG_DEBUG, "DB language to be used: %s", opts->language);

    retval = pam_get_item(pamh, PAM_USER, (void*) &username);
    if (!username || retval != PAM_SUCCESS) {
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
    if (!rhost) {
        pam_syslog(pamh, LOG_INFO, "rhost is NULL, allowing");
        free_opts(opts);
        free_locations(geo);
        return PAM_SUCCESS;
    }

    retval = pam_get_item(pamh, PAM_SERVICE, (void*) &srv);
    if (!srv || retval != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_CRIT, "error requesting service name");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    opts->service_file = malloc(PATH_MAX);
    if (!opts->service_file) {
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

    retval = MMDB_open(opts->geoip_db, MMDB_MODE_MMAP, &gi);
    if (retval != MMDB_SUCCESS) {
        pam_syslog(pamh, LOG_CRIT, "failed to open geoip db (%s - %s): %m", opts->geoip_db, MMDB_strerror(retval));
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    gi_type = gi.metadata.database_type;
    if (opts->debug) {
        pam_syslog(pamh, LOG_DEBUG, "GeoIP database type: %s", gi_type);
        pam_syslog(pamh, LOG_DEBUG, "GeoIP IP version: %d", gi.metadata.ip_version);
    }
    if (!gi_type || (!strstr(gi_type, "Country") && !strstr(gi_type, "City"))) {
        pam_syslog(pamh, LOG_CRIT, "Not a City or Country DB. Reported GeoIP DB type = %s", gi_type);
        MMDB_close(&gi);
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    opts->is_city_db = strstr(gi_type, "City") ? 1 : 0;
    if (opts->debug) pam_syslog(pamh, LOG_DEBUG, "GeoIP DB is City DB: %s", opts->is_city_db ? "yes" : "no");

    rec = MMDB_lookup_string(&gi, rhost, &gai_error, &mmdb_error);
    if (gai_error || mmdb_error != MMDB_SUCCESS || !rec.found_entry) {
        pam_syslog(pamh, LOG_INFO, "no record detected for %s, setting GeoIP to 'UNKNOWN,*'", rhost);
        geo->city = strdup("*");
        geo->country = strdup("UNKNOWN");
    }
    else {
        if (opts->is_city_db) {
            retval = MMDB_get_value(&rec.entry, &entry_data, "city", "names", opts->language, NULL);
            if (retval == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING && entry_data.data_size > 0) geo->city = strndup(entry_data.utf8_string, entry_data.data_size);
            else geo->city = strdup("*");

            retval = MMDB_get_value(&rec.entry, &entry_data, "location", "latitude", NULL);
            if (retval == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) geo->latitude = entry_data.double_value;

            retval = MMDB_get_value(&rec.entry, &entry_data, "location", "longitude", NULL);
            if (retval == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) geo->longitude = entry_data.double_value;
        }
        else geo->city = strdup("*");

        retval = MMDB_get_value(&rec.entry, &entry_data, "country", "iso_code", NULL);
        if (retval == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING && entry_data.data_size > 0) geo->country = strndup(entry_data.utf8_string, entry_data.data_size);
        else geo->country = strdup("UNKNOWN");
    }

    MMDB_close(&gi);

    if (!geo->city || !geo->country) {
        pam_syslog(pamh, LOG_CRIT, "malloc error 'geo->{city,country}': %m");
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    if (opts->debug) {
        pam_syslog(pamh, LOG_DEBUG, "GeoIP record for %s: %s,%s", rhost, geo->country, geo->city);
        if (strcmp(geo->country, "UNKNOWN") && opts->is_city_db) pam_syslog(pamh, LOG_DEBUG, "GeoIP coordinates for %s: %f,%f", rhost, geo->latitude, geo->longitude);
    }

    if ((fh = fopen(opts->service_file, "r")) != NULL) {
        opts->by_service = 1;
        if (opts->debug) pam_syslog(pamh, LOG_DEBUG, "using services file %s", opts->service_file);
    }
    else if ((fh = fopen(opts->system_file, "r")) == NULL) {
        pam_syslog(pamh, LOG_CRIT, "error opening %s: %m", opts->system_file);
        free_opts(opts);
        free_locations(geo);
        return PAM_SERVICE_ERR;
    }

    action = opts->action;
    char location[LINE_LENGTH];
    while (fgets(buf, LINE_LENGTH, fh) != NULL) {
        char *line, *ptr;
        char domain[LINE_LENGTH], service[LINE_LENGTH];

        action = opts->action;
        line = buf;
        while (*line && isspace(*line)) ++line; /* skip the leading white space */

        ptr = strchr(line,'#');
        if (ptr) *ptr = 0; /* Rip off the comments */
        ptr = strchr(line,'\n');
        if (ptr) *ptr = 0; /* Rip off the newline char */
        if (!line[0]) continue; /* Anything left ? */

        action = parse_conf_line(pamh, line, domain, opts->by_service ? NULL : service, location);
        if (action < 0) { /* parsing failed */
            action = opts->action;
            continue;
        }

        if (!opts->by_service && !check_service(pamh, service, srv)) continue;
        if (!strcmp(domain, "*") || !strcmp(username, domain)) {
            if (check_location(pamh, opts, location, geo)) break;
        }
        else if (domain[0] == '@' && pam_modutil_user_in_group_nam_nam(pamh, username, domain+1) && check_location(pamh, opts, location, geo)) break;
    }

    fclose(fh);
    free_locations(geo);
    free_opts(opts);

    switch (action) {
    case PAM_SUCCESS:
        pam_syslog(pamh, LOG_DEBUG, "location %s allowed for user %s from %s", location, username, rhost);
        break;
    case PAM_PERM_DENIED:
        pam_syslog(pamh, LOG_DEBUG, "location %s denied for user %s from %s", location, username, rhost);
        break;
    case PAM_IGNORE:
        pam_syslog(pamh, LOG_DEBUG, "location %s ignored for user %s from %s", location, username, rhost);
        break;
    default: /* should not happen */
        pam_syslog(pamh, LOG_DEBUG, "location status: %d for user %s from %s", action, username, rhost);
        break;
    };
    return action;
}

/*
 * vim: ts=4 sw=4 expandtab
 */
