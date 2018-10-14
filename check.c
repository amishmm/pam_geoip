/*
 * check.c - account module to check GeoIP information
 *
 * $Id$
 *
 */

#include "pam_geoip.h"

int check_service(pam_handle_t *pamh, char *services, char *srv) {
    char *str, *next;

    if (strcmp(services, "*") == 0)
        return 1;

    str = services;
    while (*services) {
        while (*str && *str != ',')
            str++;

        if (*str)
            next = str + 1;
        else
            next = "";

        *str = '\0';
        if (   (strncmp(services, srv, strlen(services)) == 0)
            || (strcmp(services, "*") == 0))
        {
            return 1;
        }

        services = next;
    }
    return 0;
}

double /* see also: http://en.wikipedia.org/wiki/Great-circle_distance */
calc_distance(float latitude, float longitude, float geo_lat, float geo_long) {
    double distance;
    float earth = 6367.46; /* km avg radius */
    /* convert grad to rad: */
    double la1 = latitude  * M_PI / 180.0,
           la2 = geo_lat   * M_PI / 180.0,
           lo1 = longitude * M_PI / 180.0,
           lo2 = geo_long  * M_PI / 180.0;

    distance = atan2(
            sqrt(
                pow(
                    cos(la2) * sin(lo1-lo2),
                    2.0
                )
                    +
                pow(
                    cos(la1) * sin(la2) - sin(la1) * cos(la2) * cos(lo1-lo2),
                    2.0
                )
            ),
            sin(la1) * sin(la2) + cos(la1) * cos(la2) * cos(lo1-lo2)
        );
    if (distance < 0.0)
        distance += 2 * M_PI;
    distance *= earth;
    return distance;
}

int
check_location(pam_handle_t *pamh,
               struct options *opts,
               char *location_string,
               struct locations *geo)
{
    struct locations *list;
    struct locations *loc;
    double distance;

    list = loc = parse_locations(pamh, opts, location_string);

    while (list) {
        if (list->country == NULL) {
            if (strcmp(geo->country, "UNKNOWN") == 0) {
                list = list->next;
                continue;
            }
            if (opts->is_city_db) {
                distance = calc_distance(list->latitude, list->longitude,
                                          geo->latitude, geo->longitude);
                if (distance <= list->radius) {
                    pam_syslog(pamh, LOG_INFO, "distance(%.3f) < radius(%3.f)",
                                                    distance, list->radius);
                    sprintf(location_string, "%.3f {%f,%f}", distance, geo->latitude, geo->longitude);
                    free_locations(loc);
                    return 1;
                }
            }
            else
                pam_syslog(pamh, LOG_INFO, "not a city db edition, ignoring distance entry");
        }
        else {
            if (opts->debug)
                pam_syslog(pamh, LOG_INFO, "location: (%s,%s) geoip: (%s,%s)",
                            list->country, list->city, geo->country, geo->city);

            if (
                (list->country[0] == '*' ||
                 strcmp(list->country, geo->country) == 0)
                    &&
                (list->city[0]    == '*' ||
                 strcmp(list->city,    geo->city   ) == 0)
            )
            {
                if (opts->debug)
                    pam_syslog(pamh, LOG_INFO, "location [%s,%s] matched: %s,%s",
                                                    geo->country, geo->city,
                                                    list->country, list->city);
                sprintf(location_string, "%s,%s", geo->country, geo->city);
                free_locations(loc);
                return 1;
            }
        }
        list = list->next;
    }
    if (loc) /* may be NULL */
         free_locations(loc);
    return 0;
}

/*
 * vim: ts=4 sw=4 expandtab
 */
