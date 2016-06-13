# opsmtools

**opsmtools** exposes the [MongoDB Ops Manager API](https://docs.opsmanager.mongodb.com/current/reference/api/)
endpoints through a simple command line script with minimal dependencies.

**not** all endpoint are supported yet, please contribute.

Supported Endpoints
-------------------

+ Getting Hosts
+ COMING SOON: Getting host metrics
+ Getting Alerts
+ Getting Alert Configurations
+ Deleting Alert Configurations
+ Migrating Alert Configuration from one Ops Mgr to another Ops Mgr instance
+ Getting clusters
+ Listing snapshots from a clusters backups
+ Downloading a particular snapshot or just the 'latest'
+ Downloading point-in-time backup
+ Restoring backups: download and deploy any backup to another MongoDB instance

Installation
------------


You need to have a version of Python installed in order to use mtools. Python
2.6.x (you will need to install ``argparse`` and ``requests``) and Python 2.7.x are currently supported. To check your Python version,
run `python --version` on the command line. Python 3.x is currently not supported.

### opsmtools Installation

#### Installation from source

The easiest way to install opsmtools is with `curl`:

    $curl -OL https://raw.githubusercontent.com/jasonmimick/opsmtools/master/opsmtools.py
    $chmod +x opsmtools.py

Or you can use your favorite method to download the single python file.

Usage
------

```
usage: opsmtools.py [-h] --host HOST --group GROUP --username USERNAME
                    --apikey APIKEY [--getClusters] [--getHosts] [--getAlerts]
                    [--getAlertConfigs] [--deleteAlertConfigs]
                    [--postAlertConfigs] [--migrateAlertConfigs]
                    [--getSnapshots] [--createRestore] [--createRestoreLatest]
                    [--createRestoreAndDeploy] [--targetHost TARGETHOST]
                    [--targetGroup TARGETGROUP]
                    [--targetUsername TARGETUSERNAME]
                    [--targetApikey TARGETAPIKEY]
                    [--targetPassword TARGETPASSWORD]
                    [--targetAuthenticationDatabase TARGETAUTHENTICATIONDATABASE]
                    [--targetAuthenticationMechanism TARGETAUTHENTICATIONMECHANISM]
                    [--alertConfigsSource ALERTCONFIGSSOURCE]
                    [--clusterId CLUSTERID] [--snapshotId SNAPSHOTID]
                    [--snapshotTimestamp SNAPSHOTTIMESTAMP]
                    [--snapshotIncrement SNAPSHOTINCREMENT]
                    [--restoreNamespace RESTORENAMESPACE]
                    [--outDirectory OUTDIRECTORY]
                    [--restoreAndDeployTempPort RESTOREANDDEPLOYTEMPPORT]
                    [--restoreAndDeployTempMongodArgs RESTOREANDDEPLOYTEMPMONGODARGS]
                    [--restoreAndDeployDropFromTarget] [--continueOnError]
                    [--verbose]

Get alerts from MongoDB Ops/Cloud Manager

optional arguments:
  -h, --help            show this help message and exit
  --getClusters         get cluster information
  --getHosts            get host information
  --getAlerts           get alerts
  --getAlertConfigs     get alert configurations
  --deleteAlertConfigs  delete ALL alert configs from host
  --postAlertConfigs    post ALL alert configs to host
  --migrateAlertConfigs
                        migrate ALL alert configs from host to target
  --getSnapshots        get list of snapshots for a given --clusterId
  --createRestore       create a restore job from a given --clusterId for a
                        given --snapshotId
  --createRestoreLatest
                        create a restore job for the lastest snapshotId
  --createRestoreAndDeploy
                        create a restore job from a given --clusterId for a
                        given --snapshotId (or --snapshotTimestamp,
                        --snapshotIncrement is optional), download and unpack
                        it, then deploy data in --restoreNamespace to
                        --targetHost NOTE: you must have the same or higher
                        version of Mongo binaries installed on the machine
                        running this script as running on the --targetHost!
  --targetHost TARGETHOST
                        target OpsMgr/MongoDB host with protocol and port
  --targetGroup TARGETGROUP
                        target OpsMgr group id
  --targetUsername TARGETUSERNAME
                        target OpsMgr/MongoDB host user name
  --targetApikey TARGETAPIKEY
                        target OpsMgr api key for target user
  --targetPassword TARGETPASSWORD
                        target MongoDB instance password for target user
  --targetAuthenticationDatabase TARGETAUTHENTICATIONDATABASE
                        target MongoDB instance authentication database target
                        user
  --targetAuthenticationMechanism TARGETAUTHENTICATIONMECHANISM
                        target MongoDB instance authentication mechanism
                        target user
  --alertConfigsSource ALERTCONFIGSSOURCE
                        A file containing JSON alert configs or "-" for STDIN
  --clusterId CLUSTERID
                        id of replica set or sharded cluster for snapshots
  --snapshotId SNAPSHOTID
                        id of a snapshot to restore
  --snapshotTimestamp SNAPSHOTTIMESTAMP
                        point-in-time restore timestamp, format
                        2014-07-09T09:20:00Z
  --snapshotIncrement SNAPSHOTINCREMENT
                        point-in-time restore increment, a positive integer
  --restoreNamespace RESTORENAMESPACE
                        Namespace(s) to restore from snapshot. Use "*" for all
                        databases. Use "foo.*" for all collections in the foo
                        database. Use "foo.bar" for just the bar collection in
                        the foo database.
  --outDirectory OUTDIRECTORY
                        optional directory to save downloaded snapshot
  --restoreAndDeployTempPort RESTOREANDDEPLOYTEMPPORT
                        optional port number to run temporary mongod to
                        restore snapshot from, default is 27229
  --restoreAndDeployTempMongodArgs RESTOREANDDEPLOYTEMPMONGODARGS
                        optional arguments for temp mongod to restore snapshot
                        from.
  --restoreAndDeployDropFromTarget
                        optional arguments for mongorestore process used to
                        restore snapshot to --targetHost. For example "--drop"
                        to force a drop of the collection(s) to be restored.
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

Optional dependencies
---------------------

Use ```pip``` to install ```terminaltables``` to get nice ascii
tables when calling ```--getAlerts``` and other operations.

Examples
--------

If you are getting errors, remember to add the ```--verbose``` flag
to your command for useful debugging information.

*Example 1:* Get alerts.

```
$./opsmtools.py --host http://my.opsmgr.server:8080 \
               --group 57598b14e4b01b9f37aadaf8 \
               --username jason.mimick@mongodb.com --apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
               --getAlerts
+Alerts from http://my.opsmgr.server:8080--------------------------------+
| eventTypeName         | status | created              | replicaSetName |
+-----------------------+--------+----------------------+----------------+
| MONITORING_AGENT_DOWN | CLOSED | 2016-06-13T17:34:21Z |                |
+-----------------------+--------+----------------------+----------------+
|                       |        | Number alerts        | 4              |
+-----------------------+--------+----------------------+----------------+
```

*Example 2:* Restore a backup from Ops Manager to another MongoDB instance:

```
./opsmtools.py --host http://ec2-127-0-0-1.compute-1.amazonaws.com:8080 \
               --group 57598b14e4b01b9f37aadaf8 \
               --username jason.mimick@mongodb.com --apikey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
               --clusterId 575ec8aee4b0fc4aec781dfb --outDirectory ~/work/dbdump/ \
               --snapshotTimestamp 2016-06-13T15:15:48Z \
               --targetHost ec2-127-0-0-91.compute-1.amazonaws.com:27102 \
               --restoreNamespace test.foo \
               --restoreAndDeployTempPort 29299 \
               --restoreAndDeployDropFromTarget \
               --createRestoreAndDeploy
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
