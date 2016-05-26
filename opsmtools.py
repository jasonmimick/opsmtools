#!/usr/bin/env python
#
# opsmtools.py - expose various MongoDB
# Ops Manager API endpoint through a simple
# command line script.
#
# Installation:
# pip install requests,terminaltables
#
import sys, os
import argparse
import requests
import json
import copy
from requests.auth import HTTPDigestAuth
import time


# verbose print message only if args.verbose=True
def vprint(message,args):
    if args.verbose==True:
        print message

# print out list of snapshots for a given cluster/replset id
def get_snapshots(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/clusters/"+args.clusterId+"/snapshots"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    hosts_json = response.json()
    vprint(hosts_json,args)
    table_data = [
        ['created','expires','complete','replicaSetName','id','parts']
    ]
    for host in hosts_json['results']:
        row = []
        part_data = [
                [ 'replicaSetName', 'storageSizeBytes', 'mongodbVersion', 'typeName','fileSizeBytes','dataSizeBytes']
        ]
        for column in table_data[0]:
            if column=='parts':
                parts = []
                for part in host['parts']:
                    for pcol in part_data[0]:
                        parts.append( pcol + ":" + str( part.get(pcol) ) )
                    parts.append("++++++++++++++")
                    row.append(str.join("\n",parts))
            elif column=='created':
                row.append( str( host.get('created').get('date') ) )
            else:
                row.append( str( host.get(column) ) )
        table_data.append( row )

    table_data.append(['','','Number of snapshots',str(hosts_json['totalCount'])])

    host_info = 'Snapshots from ' + args.host + " for clusterId=" + args.clusterId

    if AsciiTable:
        table = AsciiTable( table_data, host_info );
        table.inner_footing_row_border = True
        print table.table
    else:
        import pprint
        pprint.pprint(table_data)

# create a restore job for a given snapshotId
def create_restore(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    headers = { "Content-Type" : "application/json" }
    snapshotInfo = { "snapshotId" : args.snapshotId }
    vprint("============= POST data ==============",args)
    vprint( json.dumps(snapshotInfo),args )
    vprint("============= end POST data ==============",args)
    url=args.host+"/api/public/v1.0/groups/"+args.group+"/clusters/"+args.clusterId+"/restoreJobs"
    vprint(url,args)
    response = requests.post(url,
        auth=HTTPDigestAuth(args.username,args.apikey),
        data=json.dumps(snapshotInfo),
        headers=headers)
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)
    # poll until restore Job is complete
    restore_json = response.json();
    restoreUrl = restore_json.get('results')[0].get('links')[0].get('href')
    print("Restore job started: " + restoreUrl)
    restoreStatus = restore_json.get('statusName')
    while  restoreStatus != "FINISHED":
        print("Restore of snapshot not complete.")
        time.sleep(5)
        response = requests.get(restoreUrl,
            auth=HTTPDigestAuth(args.username,args.apikey),
            headers=headers);
        restore_json = response.json()
        vprint("======= restore_json =========",args)
        vprint(restore_json,args)
        vprint("======= restore_json =========",args)
        restoreUrl = restore_json.get('links')[0].get('href')
        restoreStatus = restore_json.get('statusName')
    print "Restore complete."
    downloadUrl = restore_json.get('delivery').get("url")
    filename = downloadUrl.split('/')[-1]
    if hasattr(args,'outDirectory'):
        if not args.outDirectory.endswith(os.sep):
            args.outDirectory = args.outDirectory + os.sep
        filename = args.outDirectory + filename
    print "Downloading from " + downloadUrl + "saving to " + filename
    response = requests.get(downloadUrl,
            auth=HTTPDigestAuth(args.username,args.apikey),
            stream=True)
    chunk_size = 2048
    with open(filename, 'wb') as fd:
        for chunk in response.iter_content(chunk_size):
            fd.write(chunk)
    print("Snapshot download complete.")


    # download the respore

def create_latest_restore(args):
    vprint("create_restore_latest",args)
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/clusters/"+args.clusterId+"/snapshots"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    snaps_json = response.json()
    vprint(snaps_json,args)
    snapshotId = snaps_json.get('results')[0].get('id')
    args.snapshotId = snapshotId
    create_restore(args)

# print out nice table of hosts & id's
def get_hosts(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/hosts/"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    hosts_json = response.json()

    table_data = [
        ['hostname','id','clusterId','version','typeName','replicaSetName','replicaStateName','lastPing']
    ]

    for host in hosts_json['results']:
        row = []
        for column in table_data[0]:
            row.append( str( host.get(column) ) )
        table_data.append( row );

    table_data.append(['','','Number of hosts',str(hosts_json['totalCount'])])

    host_info = 'Hosts from ' + args.host

    if AsciiTable:
        table = AsciiTable( table_data, host_info );
        table.inner_footing_row_border = True
        print table.table
    else:
        import pprint
        pprint.pprint(table_data)


# print out list of clusters.
def get_clusters(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/clusters/"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    hosts_json = response.json()
    vprint(hosts_json,args)
    table_data = [
        ['clusterName','id','typeName','replicaSetName','lastHeartbeat']
    ]

    for host in hosts_json['results']:
        row = []
        for column in table_data[0]:
            row.append( str( host.get(column) ) )
        table_data.append( row );

    table_data.append(['','','Number of clusters',str(hosts_json['totalCount'])])

    host_info = 'Clusters from ' + args.host

    if AsciiTable:
        table = AsciiTable( table_data, host_info );
        table.inner_footing_row_border = True
        print table.table
    else:
        import pprint
        pprint.pprint(table_data)

# print out nice table of hosts & id's
def get_hosts(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/hosts/"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    hosts_json = response.json()

    table_data = [
        ['hostname','id','clusterId','version','typeName','replicaSetName','replicaStateName','lastPing']
    ]

    for host in hosts_json['results']:
        row = []
        for column in table_data[0]:
            row.append( str( host.get(column) ) )
        table_data.append( row );

    table_data.append(['','','Number of hosts',str(hosts_json['totalCount'])])

    host_info = 'Hosts from ' + args.host

    if AsciiTable:
        table = AsciiTable( table_data, host_info );
        table.inner_footing_row_border = True
        print table.table
    else:
        import pprint
        pprint.pprint(table_data)


def get_alerts(args):
    try:
        from terminaltables import AsciiTable
    except ImportError:
        AsciiTable = False
        pass
    host = args.host
    group_id = args.group
    user_name = args.username
    api_key = args.apikey
    response= requests.get(host+"/api/public/v1.0/groups/"+group_id+"/alerts/"
             ,auth=HTTPDigestAuth(user_name,api_key))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    alerts_json = response.json()

    table_data = [
        [   'eventTypeName','status','created','replicaSetName']
    ]

    for alert in alerts_json['results']:
        row = [ str(alert.get('eventTypeName'))
        , str(alert.get('status'))
        , str(alert.get('created'))
        , str(alert.get('replicaSetName',''))]
    table_data.append( row );

    table_data.append(['','','Number alerts',str(alerts_json['totalCount'])])

    host_info = 'Alerts from ' + host

    if AsciiTable:
        table = AsciiTable( table_data, host_info );
        table.inner_footing_row_border = True
        print table.table
    else:
        import pprint
        pprint.pprint(table_data)

def get_alert_configs(args):
    response = requests.get(args.host
            +"/api/public/v1.0/groups/"
            +args.group+"/alertConfigs"
            ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    alert_configs = json.dumps(response.json())
    print(alert_configs)


def delete_alert_configs(args):
    print('delete_alert_configs')
    print( vars(args) )
    deleted_alerts = 0
    failed_deletions = 0
    alert_configs_raw = requests.get(host+"/api/public/v1.0/groups/"+group_id+"/alertConfigs",
                      auth=HTTPDigestAuth(user_name,api_key))

    alert_configs = alert_configs_raw.json()
    vprint("============= SOURCE alert data ==============",args)
    vprint( json.dumps(alert_configs),args )
    vprint("============= end SOURCE alert data ==============",args)

    for alert in alert_configs["results"]:
        #url = "http://requestb.in/15ftkhl1"
        url = host+"/api/public/v1.0/groups/"+args.group+"/alertConfigs/"+alert["id"]
        response = requests.delete(url,
                auth=HTTPDigestAuth(args.username,args.apikey))
        vprint("============= response ==============",args)
        vprint( vars(response),args )
        vprint("============= end response ==============",args)
        if args.continueOnError and (response.status_code != requests.codes.ok):
            print "ERROR %s %s" % (response.status_code,response.reason)
            print( "Failed migration alert JSON:" )
            print json.dumps(new_alert)
            failed_deletions += 1
        else:
            response.raise_for_status()
            deleted_alerts += 1
    print "Deleted %d alerts to %s (%d failures)" % (deleted_alerts,args.targetHost,failed_deletions)

    print( vars(response) )

def post_alert_configs(args):
    print('post_alert_configs')
    print( vars(args) )
    if ( args.alertConfigsSource == "-" ):
        data = sys.stdin.read()
    else:
        data = open( args.alertConfigsSource, 'r').read()
    print data
    alert_configs = json.loads(data)
    vprint("============= SOURCE alert data ==============",args)
    vprint( json.dumps(alert_configs),args )
    vprint("============= end SOURCE alert data ==============",args)
    args.targetHost = args.host
    args.targetGroup = args.group
    args.targetApikey = args.apikey
    args.targetUsername = args.username
    __post_alert_configs(args,alert_configs)

def migrate_alert_configs(args):
    print('migrate_alert_configs');
    print( vars(args) )
    response = requests.get(args.host+
            "/api/public/v1.0/groups/"+args.group+"/alertConfigs"
            ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    alert_configs = response.json()
    __post_alert_configs(args,alert_configs)

def __post_alert_configs(args,alert_configs):
    migrated_alerts = 0
    failed_migrations = 0
    new_alert_configs = {}
    new_alert_configs['results']=[]
    for alert in alert_configs['results']:
        new_alert = copy.deepcopy(alert)
        vprint("============= SOURCE alert data ==============",args)
        vprint( json.dumps(alert),args )
        vprint("============= end SOURCE alert data ==============",args)
        new_alert['groupId'] = args.targetGroup
        if ( alert.has_key('matchers') ):
            new_alert['matchers'] = []
        del new_alert['links']
        del new_alert['matchers']
        del new_alert['id']
        del new_alert['created']
        del new_alert['updated']
        #url = "http://requestb.in/11gd5mh1"
        url = args.targetHost+"/api/public/v1.0/groups/"+args.targetGroup+"/alertConfigs/"
        headers = { "Content-Type" : "application/json" }
        vprint("============= POST data ==============",args)
        vprint( json.dumps(new_alert),args )
        vprint("============= end POST data ==============",args)

        response = requests.post(url,
                    auth=HTTPDigestAuth(args.targetUsername,args.targetApikey),
                    data=json.dumps(new_alert),
                    headers=headers)
        vprint("============= response ==============",args)
        vprint( vars(response),args )
        vprint("============= end response ==============",args)
        if args.continueOnError and (response.status_code != requests.codes.created):
            print "ERROR %s %s" % (response.status_code,response.reason)
            print( "Failed migration alert JSON:" )
            print json.dumps(new_alert)
            failed_migrations += 1
        else:
            response.raise_for_status()
            migrated_alerts += 1
    print "Migrated %d alerts to %s (%d failures)" % (migrated_alerts,args.targetHost,failed_migrations)

# "main"
parser = argparse.ArgumentParser(description="Get alerts from MongoDB Ops/Cloud Manager")
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument("--host"
        ,help='the OpsMgr host with protocol and port, e.g. http://server.com:8080'
        ,required=True)
requiredNamed.add_argument("--group"
        ,help='the OpsMgr group id'
        ,required=True)
requiredNamed.add_argument("--username"
        ,help='OpsMgr user name'
        ,required=True)
requiredNamed.add_argument("--apikey"
        ,help='OpsMgr api key for the user'
        ,required=True)

parser.add_argument("--getClusters",dest='action', action='store_const'
        ,const=get_clusters
        ,help='get cluster information')
parser.add_argument("--getHosts",dest='action', action='store_const'
        ,const=get_hosts
        ,help='get host information')
parser.add_argument("--getAlerts",dest='action', action='store_const'
        ,const=get_alerts
        ,help='get alerts')
parser.add_argument("--getAlertConfigs",dest='action', action='store_const'
        ,const=get_alert_configs
        ,help='get alert configurations')
parser.add_argument("--deleteAlertConfigs",dest='action', action='store_const'
        ,const=delete_alert_configs
        ,help='delete ALL alert configs from host')
parser.add_argument("--postAlertConfigs",dest='action', action='store_const'
        ,const=post_alert_configs
        ,help='post ALL alert configs to host')
parser.add_argument("--migrateAlertConfigs",dest='action', action='store_const'
        ,const=migrate_alert_configs
        ,help='migrate ALL alert configs from host to target')
parser.add_argument("--getSnapshots",dest='action', action='store_const'
        ,const=get_snapshots
        ,help='get list of snapshots for a given --clusterId')
parser.add_argument("--createRestore",dest='action', action='store_const'
        ,const=create_restore
        ,help='create a restore job from a given --clusterId for a given --snapshotId')
parser.add_argument("--createRestoreLatest",dest='action', action='store_const'
        ,const=create_latest_restore
        ,help='create a restore job for the lastest snapshotId')
parser.add_argument("--targetHost"
        ,help='target OpsMgr host with protocol and port')
parser.add_argument("--targetGroup"
        ,help='target OpsMgr group id')
parser.add_argument("--targetUsername"
        ,help='target OpsMgr host user name')
parser.add_argument("--targetApikey"
        ,help='target OpsMgr api key for target user')
parser.add_argument("--alertConfigsSource"
        ,help='A file containing JSON alert configs or "-" for STDIN')
parser.add_argument("--clusterId"
        ,help='id of replica set or sharded cluster for snapshots')
parser.add_argument("--snapshotId"
        ,help='id of a snapshot to restore')
parser.add_argument("--outDirectory"
        ,help='optional directory to save downloaded snapshot')
parser.add_argument("--continueOnError", action='store_true', default=False
        ,help='for operations that issue multiple API calls, set this flag to fail to report errors but keep going')
parser.add_argument("--verbose", action='store_true', default=False
        ,help='enable versbose output for troubleshooting')

parsed_args = parser.parse_args()

vprint( vars(parsed_args), parsed_args )

if parsed_args.action is None:
    parser.parse_args(['-h'])
else:
    parsed_args.action(parsed_args)
