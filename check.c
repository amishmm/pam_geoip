/*
 * check.c - account module to check GeoIP information
 *
 * $Id$
 *
 */

#include "pam_geoip.h"

int check_service(pam_handle_t *pamh, char *services, char *srv)
{
    char *str, *next;
    if (!strcmp(services, "*")) return 1;

    str = services;
    while (*services) {
        while (*str && *str != ',') ++str;

        if (*str) next = str + 1;
        else next = "";

        *str = 0;
        if (!strncmp(services, srv, strlen(services)) || !strcmp(services, "*")) return 1;

        services = next;
    }
    return 0;
}


/* see also: http://en.wikipedia.org/wiki/Great-circle_distance */
double calc_distance(double latitude, double longitude, double geo_lat, double geo_long)
{
    double distance;
    float earth = 6367.46; /* km avg radius */
    /* convert grad to rad: */
    double la1 = latitude  * M_PI / 180.0,
           la2 = geo_lat   * M_PI / 180.0,
           lo1 = longitude * M_PI / 180.0,
           lo2 = geo_long  * M_PI / 180.0;

    distance = atan2(sqrt(
                          pow(cos(la2) * sin(lo1-lo2), 2.0) +
                          pow(cos(la1) * sin(la2) - sin(la1) * cos(la2) * cos(lo1-lo2), 2.0)
                     ),
                     sin(la1) * sin(la2) + cos(la1) * cos(la2) * cos(lo1-lo2)
               );
    if (distance < 0.0) distance += 2 * M_PI;
    distance *= earth;
    return distance;
}


int check_location(pam_handle_t *pamh, struct options *opts, char *location_string, struct locations *geo)
{
    int retval = 0;
    double distance;
    struct locations *list, *loc;

    list = loc = parse_locations(pamh, opts, location_string);
    while (list) {
        if (!list->country) {
            if (!strcmp(geo->country, "UNKNOWN")) {
                list = list->next;
                continue;
            }
            if (opts->is_city_db) {
                distance = calc_distance(list->latitude, list->longitude, geo->latitude, geo->longitude);
                if (distance <= list->radius) {
                    pam_syslog(pamh, LOG_INFO, "distance(%.3f) < radius(%3.f)", distance, list->radius);
                    sprintf(location_string, "%.3f {%f,%f}", distance, geo->latitude, geo->longitude);
                    retval = 1;
                    break;
                }
            }
            else pam_syslog(pamh, LOG_INFO, "not a city db edition, ignoring distance entry");
        }
        else {
            if (opts->debug) pam_syslog(pamh, LOG_INFO, "location: (%s,%s) geoip: (%s,%s)", list->country, list->city, geo->country, geo->city);
            if ((list->country[0] == '*' || !strcmp(list->country, geo->country)) &&
                (list->city[0] == '*' || !strcmp(list->city, geo->city))
               ) {
                if (opts->debug) pam_syslog(pamh, LOG_INFO, "location [%s,%s] matched: %s,%s", geo->country, geo->city, list->country, list->city);
                sprintf(location_string, "%s,%s", geo->country, geo->city);
                retval = 1;
                break;
            }
        }
        list = list->next;
    }
    if (loc) free_locations(loc);
    return retval;
}

/*
 * vim: ts=4 sw=4 expandtab
 */
