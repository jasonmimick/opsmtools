# opsmtools

**opsmtools** exposes the [MongoDB Ops Manager API](https://docs.opsmanager.mongodb.com/current/reference/api/)
endpoints through a simple command line script with minimal dependencies.

**not** all endpoint are supported yet, please contribute.

Supported Endpoints
-------------------

+ Getting Alerts
+ Getting Alert Configurations
+ Deleting Alert Configurations
+ Migrating Alert Configuration from one Ops Mgr to another Ops Mgr instance

Installation
------------


You need to have a version of Python installed in order to use mtools. Python
2.6.x and Python 2.7.x are currently supported. To check your Python version,
run `python --version` on the command line. Python 3.x is currently not supported.

### opsmtools Installation

#### Installation form source

The easiest way to install opsmtools is with `curl`:

    curl -OL https://raw.githubusercontent.com/jasonmimick/opsmtools/master/opsmtools.py

#### Installation with `pip`

To install opsmtools is via `pip`. From the command line, run:

    pip install opsmtools

You need to have `pip` installed for this to work. If you don't have `pip` installed yet,
try `sudo easy_install pip` from the command line first, or follow the instructions provided on the
[pip installation page](http://www.pip-installer.org/en/latest/installing.html#using-the-installer).

Depending on your user rights, it may complain about not having permissions to install the module.
In that case, you need to add `sudo` in front of the command.

Usage
------

```
usage: opsmtools [-h] --host HOST --group GROUP --username USERNAME --apikey
                 APIKEY [--getAlerts] [--getAlertConfigs]
                 [--deleteAlertConfigs] [--migrateAlertConfigs]
                 [--targetHost TARGETHOST] [--targetGroup TARGETGROUP]
                 [--targetUsername TARGETUSERNAME]
                 [--targetApikey TARGETAPIKEY] [--continueOnError] [--verbose]

Get alerts from MongoDB Ops/Cloud Manager

optional arguments:
  -h, --help            show this help message and exit
  --getAlerts           get alerts
  --getAlertConfigs     get alert configurations
  --deleteAlertConfigs  delete ALL alert configs from host
  --migrateAlertConfigs
                        migrate ALL alert configs from host to target
  --targetHost TARGETHOST
                        target OpsMgr host with protocol and port
  --targetGroup TARGETGROUP
                        target OpsMgr group id
  --targetUsername TARGETUSERNAME
                        target OpsMgr host user name
  --targetApikey TARGETAPIKEY
                        target OpsMgr api key for target user
  --continueOnError     for operations that issue multiple API calls, set this
                        flag to fail to report errors but keep going
  --verbose             enable versbose output for troubleshooting

required named arguments:
  --host HOST           the OpsMgr host with protocol and port, e.g.
                        http://server.com:8080
  --group GROUP         the OpsMgr group id
  --username USERNAME   OpsMgr user name
  --apikey APIKEY       OpsMgr api key for the user
```

Credits
-------

opsmtools was inspired by (and borrows heavily from) the excellent [mtools](https://github.com/rueckstiess/mtools) suite.
Thanks, Thomas!

Disclaimer
----------

This software is not supported by [MongoDB, Inc.](http://www.mongodb.com) under any of their commercial support subscriptions or otherwise.
Any usage of opsmtools is at your own risk.
Bug reports, feature requests and questions can be posted in the [Issues](https://github.com/jasonmimick/opsmtools/issues?state=open) section here on github.

Author: [jason.mimick@mongodb.com](jason.mimick@mongodb.com)
