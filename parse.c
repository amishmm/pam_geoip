/*
 * parse.c - account module to check GeoIP information
 *
 * $Id$
 *
 */

#include "pam_geoip.h"

struct locations *parse_locations(pam_handle_t *pamh, struct options *opts, char *location_string)
{
    float radius;
    double latitude, longitude;
    struct locations *entry, *walker, *list;
    char *country, *city, *single, *end, *next;
    char *string = strdup(location_string ? location_string : "");

    if (!string) {
        pam_syslog(pamh, LOG_CRIT, "failed to strdup: %m");
        return NULL;
    }

    entry = walker = list = NULL;
    single = string;
    while (*single) {
        if (isspace(*single)) {
            ++single;
            continue;
        }

        country = NULL;
        city = NULL;
        end = single;

        while (*end && *end != ';') ++end;

        if (*end) next = end + 1;
        else next = end;

        *end-- = 0;
        while (isspace(*end)) *end-- = 0;
        if (!single[0]) {
            single = next;
            continue;
        }

        if (sscanf(single, "%f { %lf , %lf }", &radius, &latitude, &longitude) == 3) {
            if (fabs(latitude) > 90.0 || fabs(longitude) > 180.0) {
                pam_syslog(pamh, LOG_WARNING, "illegal value(s) in LAT/LONG: %f, %f", latitude, longitude);
                single = next;
                continue;
            }
        }
        else {
            country = single;
            while (*single && *single != ',') ++single;

            /* single is now at the end of country */
            if (*single) city = single + 1;
            else city = "*";

            *single-- = 0;
            while (isspace(*single)) *single-- = 0;
            if (!country[0]) country = "*";

            while (isspace(*city)) ++city;
            if (!city[0]) city = "*";
        }
        single = next;

        entry = malloc(sizeof(struct locations));
        if (!entry) {
            pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
            free(string);
            return NULL;
        }
        entry->next = NULL;

        if (!country) {
            entry->radius = radius;
            entry->longitude = longitude;
            entry->latitude = latitude;
            entry->country = NULL;
            entry->city = NULL;
        }
        else {
            entry->country = strdup(country);
            if (!entry->country) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry);
                free(string);
                return NULL;
            }

            entry->city = strdup(city);
            if (!entry->city) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry->country);
                free(entry);
                free(string);
                return NULL;
            }
        }

        if (!list) list = entry;
        else walker->next = entry;
        walker = entry;
    }
    free(string);
    return list;
}


int parse_action(pam_handle_t *pamh, char *name)
{
    int action = -1;
    if (!strcmp(name, "deny")) action = PAM_PERM_DENIED;
    else if (!strcmp(name, "allow")) action = PAM_SUCCESS;
    else if (!strcmp(name, "ignore")) action = PAM_IGNORE;
    else pam_syslog(pamh, LOG_WARNING, "invalid action '%s' - skipped", name);
    return action;
}


int parse_conf_line(pam_handle_t *pamh, char *line, char *domain, char *service, char *location)
{
    char *str;
    char action[LINE_LENGTH+1];

    if ((service && sscanf(line, "%s %s %s %[^\n]", domain, service, action, location) != 4) ||
        (!service && sscanf(line, "%s %s %[^\n]", domain, action, location) != 3)
       ) {
        pam_syslog(pamh, LOG_WARNING, "invalid line '%s' - skipped", line);
        return -1;
    }

    /* remove white space from the end */
    str = location + strlen(location) - 1;
    while (isspace(*str)) *str-- = 0;

    return parse_action(pamh, action);
}

/*
 * vim: ts=4 sw=4 expandtab
 */
