/*
 * parse.c - account module to check GeoIP information
 *
 * $Id$
 *
 */
#include "pam_geoip.h"

struct locations *
parse_locations(pam_handle_t *pamh,
                struct options *opts,
                char *location_string)
{
    struct locations *entry  = NULL;
    struct locations *walker = NULL;
    struct locations *list   = NULL;
    char *single, *end, *next;
    char *country, *city;
    char *string = strdup(location_string);
    float latitude;
    float longitude;
    float radius;

    single = string;
    while (*single) {
        if (isspace(*single)) {
            single++;
            continue;
        }

        country = NULL;
        city    = NULL;
        end     = single;

        while (*end && *end != ';')
            end++;

        if (*end)
            next = end + 1;
        else
            next = end;

        *end = '\0';
        end--;
        while (isspace(*end)) {
            *end = '\0';
            end--;
        }

        if (strlen(single) == 0) {
            single = next;
            continue;
        }

        if (sscanf(single, "%f { %f , %f }", &radius, &latitude, &longitude)
            == 3)
        {
            if (fabsf(latitude) > 90.0 || fabsf(longitude) > 180.0) {
                pam_syslog(pamh, LOG_WARNING,
                        "illegal value(s) in LAT/LONG: %f, %f",
                        latitude, longitude);
                single = next;
                continue;
            }
        }
        else {
            country = single;
            while (*single && *single != ',')
                single++;

            /* single is now at the end of country */
            if (*single)
                city = single + 1;
            else
                city = "*";

            *single = '\0';
            single--;
            while (isspace(*single)) {
                *single = '\0';
                single--;
            }
            if (strlen(country) == 0)
                country = "*";

            while (isspace(*city))
                city++;
            if (strlen(city) == 0)
                city = "*";
        }
        single = next;

        entry = malloc(sizeof(struct locations));
        if (entry == NULL) {
            pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
            return NULL;
        }
        entry->next    = NULL;

        if (country == NULL) {
            entry->radius    = radius;
            entry->longitude = longitude;
            entry->latitude  = latitude;
            entry->country   = NULL;
            entry->city      = NULL;
        }
        else {
            entry->country = strdup(country);
            if (entry->country == NULL) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry);
                return NULL;
            }

            entry->city = strdup(city);
            if (entry->city == NULL) {
                pam_syslog(pamh, LOG_CRIT, "failed to malloc: %m");
                free(entry);
                return NULL;
            }
        }

        if (list == NULL)
            list = entry;
        else {
            walker = list;
            while (walker->next)
                walker = walker->next;
            walker->next = entry;
        }
    }
    if (string)
        free(string); /* strdup'd */
    return list;
}

int parse_action(pam_handle_t *pamh, char *name) {
    int action = -1;
    if (strcmp(name, "deny") == 0)
        action = PAM_PERM_DENIED;
    else if (strcmp(name, "allow") == 0)
        action = PAM_SUCCESS;
    else if (strcmp(name, "ignore") == 0)
        action = PAM_IGNORE;
    else
        pam_syslog(pamh, LOG_WARNING, "invalid action '%s' - skipped", name);

    return action;
}

int
parse_line_srv(pam_handle_t *pamh,
           char *line,
           char *domain,
           char *location)
{
    char *str;
    char action[LINE_LENGTH+1];

    if (sscanf(line, "%s %s %[^\n]", domain, action, location) != 3)
    {
        pam_syslog(pamh, LOG_WARNING, "invalid line '%s' - skipped", line);
        return -1;
    }
    /* remove white space from the end */
    str = location + strlen(location) - 1;
    while (isspace(*str)) {
            *str = '\0';
            str--;
    }

    return parse_action(pamh, action);
}

int
parse_line_sys(pam_handle_t *pamh,
           char *line,
           char *domain,
           char *service,
           char *location)
{
    char *str;
    char action[LINE_LENGTH+1];

    if (sscanf(line, "%s %s %s %[^\n]", domain, service, action, location) != 4)
    {
        pam_syslog(pamh, LOG_WARNING, "invalid line '%s' - skipped", line);
        return -1;
    }

    /* remove white space from the end */
    str = location + strlen(location) - 1;
    while (isspace(*str)) {
            *str = '\0';
            str--;
    }

    return parse_action(pamh, action);
}

/*
 * vim: ts=4 sw=4 expandtab
 */
