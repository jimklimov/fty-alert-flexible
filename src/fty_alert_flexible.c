/*  =========================================================================
    fty_alert_flexible - description

    Copyright (C) 2016 - 2017 Tomas Halman

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    fty_alert_flexible - agent for creating / evaluating alerts
@discuss
@end
*/

#include "fty_alert_flexible_classes.h"

#define ACTOR_NAME      "fty-alert-flexible"
#define ENDPOINT        "ipc://@/malamute"
#define RULES_DIR        "./rules"
#define CONFIG          "/etc/fty-alert-flexible/fty-alert-flexible.cfg";
#define METRICS_PATTERN ".*";


static const char*
s_get (zconfig_t *config, const char* key, const char*dfl) {
    assert (config);
    const char *ret = (const char *)zconfig_get (config, key, dfl);
    if (!ret || streq (ret, ""))
        return dfl;
    return ret;
}

int main (int argc, char *argv [])
{
    bool  verbose               = false;
    const char *endpoint        = ENDPOINT;
    const char *config_file     = CONFIG;
    const char *rules           = RULES_DIR;
    const char *metrics_pattern = METRICS_PATTERN; 
    
    int argn;
    for (argn = 1; argn < argc; argn++) {
        const char *param = NULL;
        if (argn < argc - 1) param = argv [argn+1];

        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("fty-alert-flexible [options] ...");
            puts ("  -v|--verbose          verbose test output");
            puts ("  -h|--help             this information");
            puts ("  -e|--endpoint         malamute endpoint [ipc://@/malamute]");
            puts ("  -r|--rules            directory with rules [./rules]");
            puts ("  -c|--config           path to config file[/etc/fty-alert-flexible/fty-alert-flexible.cfg]\n");
            return 0;
        }
        else if (streq (argv [argn], "--verbose") || streq (argv [argn], "-v")) {
            verbose = true;
        }
        else if (streq (argv [argn], "--endpoint") || streq (argv [argn], "-e")) {
            if (param) endpoint = param;
            ++argn;
        }
        else if (streq (argv [argn], "--rules") || streq (argv [argn], "-r")) {
            if (param) rules = param;
            ++argn;
        }
        else if (streq (argv [argn], "--config") || streq (argv [argn], "-c")) {
            if (param) config_file = param;
            ++argn;
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //parse config file
    zconfig_t *config = zconfig_load(config_file);
    if (config) {
        // verbose
        if (streq (zconfig_get (config, "server/verbose", (verbose?"1":"0")), "1")) {
            verbose = true;
        }
        //rules
        rules = s_get (config, "server/rules", rules);
        // endpoint
        endpoint = s_get (config, "malamute/endpoint", endpoint);
        //metrics_pattern
        metrics_pattern = s_get (config, "malamute/metrics_pattern", metrics_pattern);
                
    }else{
        zsys_error ("Failed to load config file %s",config_file);
    }
    if (verbose)
        zsys_info ("fty_alert_flexible - started");
    //  Insert main code here
    zactor_t *server = zactor_new (flexible_alert_actor, NULL);
    assert (server);
    zstr_sendx (server, "BIND", endpoint, ACTOR_NAME, NULL);
    zstr_sendx (server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS, metrics_pattern, NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx (server, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (server, "LOADRULES", RULES_DIR, NULL);
    if (verbose)
        zstr_sendx (server, "VERBOSE", NULL);

    while (!zsys_interrupted) {
        zmsg_t *msg = zactor_recv (server);
        zmsg_destroy (&msg);
    }
    zactor_destroy (&server);
    if (verbose)
        zsys_info ("fty_alert_flexible - exited");

    return 0;
}
