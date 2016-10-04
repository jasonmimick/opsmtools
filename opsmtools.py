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
import datetime
import argparse
import requests
import json
import copy
from requests.auth import HTTPDigestAuth
import time
import tarfile
import subprocess, signal
import ast

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
    if args.snapshotId:
        snapshotInfo = { "snapshotId" : args.snapshotId }
    elif args.snapshotTimestamp:
        snapshotInfo = { "timestamp" : { "date" : args.snapshotTimestamp, "increment" : 0 } }
        if args.snapshotIncrement:
            snapshotInfo['timestamp']['increment'] = args.snapshotIncrement
    else:
        raise Exception("ERROR no snapshotId or no snapshotTimestamp found, required for create_restore")
    vprint("============= POST data ==============",args)
    vprint( json.dumps(snapshotInfo),args )
    vprint("============= end POST data ==============",args)
    url=args.host+"/api/public/v1.0/groups/"+args.group+"/clusters/"+args.clusterId+"/restoreJobs"
    vprint(url,args)
    response = requests.post(url,
        auth=HTTPDigestAuth(args.username,args.apikey),
        data=json.dumps(snapshotInfo),
        headers=headers)
    vprint( response.json(), args)
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
            vars(args)['outDirectory'] = args.outDirectory
        filename = args.outDirectory + filename
    print "Downloading from " + downloadUrl + " saving to " + filename
    response = requests.get(downloadUrl,
            auth=HTTPDigestAuth(args.username,args.apikey),
            stream=True)
    chunk_size = 2048
    with open(filename, 'wb') as fd:
        for chunk in response.iter_content(chunk_size):
            fd.write(chunk)
    print("Snapshot download complete.")
    vars(args)['create_restore_filename']=filename    #save for possible later processing

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

def create_restore_and_deploy(args):
    vprint("create_restore_and_deploy", args)
    create_restore(args)
    vprint("create_restore_and_deploy: args.create_restore_filename=" + args.create_restore_filename, args)
    total_size_bytes = 0
    restore_temp_dbpath = "";
    restore_directory = os.path.dirname(args.create_restore_filename)
    restore_dir_stats = os.statvfs( restore_directory )
    restore_dir_free_bytes = restore_dir_stats.f_bavail * restore_dir_stats.f_frsize
    with tarfile.open(args.create_restore_filename, "r:gz") as tfile:
        for tinfo in tfile:
            if total_size_bytes==0:
                restore_temp_dbpath = tinfo.name.split(os.sep)[0]
            vprint(tinfo.name + " size: " + str(tinfo.size),args)
            total_size_bytes += tinfo.size
        if ( total_size_bytes > restore_dir_free_bytes ):
            raise Exception('Snapshot requires ' + str(total_size_bytes) + 'bytes of free space. ' +
            'Only ' + str(restore_dir_free_bytes) + 'bytes available in ' + restore_directory)
        tfile.extractall(args.outDirectory)

    vprint("total_size_bytes="+str(total_size_bytes),args);
    vprint("restore_dir_free_bytes=+"+str(restore_dir_free_bytes),args)
    restore_temp_dbpath = restore_directory + os.sep + restore_temp_dbpath
    vprint("snapshot extracted to "+restore_temp_dbpath,args)
    # start temp mongod
    vprint("args.restoreAndDeployTempPort="+args.restoreAndDeployTempPort,args)
    mongod_cmd = "mongod --port " + args.restoreAndDeployTempPort
    mongod_cmd += " --dbpath " + restore_temp_dbpath
    mongod_cmd += " --logpath " + restore_temp_dbpath + os.sep + 'mongod.log'
    mongod_cmd += " --fork"
    if args.restoreAndDeployTempMongodArgs:
        mongod_cmd += " " + args.restoreAndDeployTempMongodArgs
    vprint("mongod_cmd="+mongod_cmd,args)
    # TODO: not sure if I want shell=True???
    subprocess.check_call(mongod_cmd, shell=True)
    vprint("temp mongod for restore started", args)
    with open(restore_temp_dbpath + os.sep + 'mongod.lock', 'r') as pidfile:
        temp_mongod_pid = pidfile.readline()
    vprint("temp_mongod_pid=" + temp_mongod_pid,args)
    #run mongoddump | mongorestore
    namespaces_to_restore = []
    if args.restoreNamespace:
        restoreNSParts = args.restoreNamespace.split('.')
        if not restoreNSParts[0]=="*":
            db = restoreNSParts[0]
            if not restoreNSParts[1]=="*":
                namespaces_to_restore.append("--db " + db + " --collection " + restoreNSParts[1])
            else:
                # need to find all the collections
                colls_s = subprocess.check_output(["mongo", "--port", args.restoreAndDeployTempPort
                    , "--eval", "db.getSiblingDB('"+db+"').getCollectionNames()", "--quiet"])
                colls = ast.literal_eval(colls_s)
                for coll in colls:
                        namespaces_to_restore.append(" --db " + db + " --collection " + coll)

        else:
            #need to find all the dbs, than all the collections
            dbs_s = subprocess.check_output(["mongo", "--port", args.restoreAndDeployTempPort
                    , "--eval" ,"db.getSiblingDB('admin').getMongo().getDBNames()", "--quiet"])
            dbs = ast.literal_eval(dbs_s)
            for db in dbs:
                colls_s = subprocess.check_output(["mongo", "--port", args.restoreAndDeployTempPort
                    , "--eval", "db.getSiblingDB('"+db+"').getCollectionNames()", "--quiet"])
                colls = ast.literal_eval(colls_s)
                for coll in colls:
                        namespaces_to_restore.append(" --db " + db + "--collection " + coll)


    mongodump_cmd = "mongodump --host localhost:" + args.restoreAndDeployTempPort
    mongodump_cmd += " --out - "     # write to SDTOUT
    vprint("mongodump_cmd="+mongodump_cmd,args);

    mongorestore_cmd = "mongorestore --host " + args.targetHost
    if args.targetUsername:
        mongorestore_cmd += " --username " + args.targetUsername
        mongorestore_cmd += " --password " + args.targetPassword
        if args.targetAuthenticationDatabase:
            mongorestore_cmd += " --authenticationDatabase " + args.targetAuthenticationDatabase
            if args.targetAuthenticationMechanism:
                mongorestore_cmd += " --authenticationMechanism " + args.targetAuthenticationMechanism
    if args.restoreAndDeployDropFromTarget:
        mongorestore_cmd += " --drop"
    mongorestore_cmd += " --dir - "  # read from STDIN



    vprint("mongorestore_cmd="+mongorestore_cmd,args)
    #spin through all the namespaces to restore since when reading & writing
    # to STDOUT/STDIN with mongodump and mongorestore and can only go 1 collection
    # at a time.
    for ns_to_restore in namespaces_to_restore:
        restore_cmd = mongodump_cmd + ns_to_restore + " | " + mongorestore_cmd + ns_to_restore
        vprint("restore_cmd="+restore_cmd,args)
        subprocess.check_call(restore_cmd, shell=True)


    #TODO: shutdown temp mongod & blow away dbpath?
    os.kill(int(temp_mongod_pid), signal.SIGKILL)

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

# retrieve information about the automation config
def get_automation_config(args):
    response= requests.get(args.host+"/api/public/v1.0/groups/"+args.group+"/automationConfig/"
             ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    hosts_json = response.json()

    print json.dumps(hosts_json, indent=4, sort_keys=True)

# modify settings within the automation config
def set_automation_config(args):
    with open(args.newAutomationConfigPath) as automation_conf_json:
        new_auto_conf = json.load(automation_conf_json)

    headers = {'content-type': 'application/json'}
    response= requests.put(args.host+"/api/public/v1.0/groups/"+args.group+"/automationConfig/"
             ,auth=HTTPDigestAuth(args.username,args.apikey)
             ,data=json.dumps(new_auto_conf)
             ,headers=headers)

    response.raise_for_status()
    vprint("============= response ==============",args)
    vprint( vars(response),args )
    vprint("============= end response ==============",args)

    response_json = response.json()

    import pprint
    pprint.pprint(response_json)

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
    if args.format=='json':
        AsciiTable = False
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
        if args.format=='json':
            print(json.dumps(alerts_json))
        else:
            import pprint
            pprint.pprint(table_data)
    return alerts_json

def process_alerts(args):
    alerts = get_alerts(args)
    for alert in alerts['results']:
        print(alert['id'])
        args.alertId = alert['id']
        #
        # custom processing goes here!
        #
        acknowledge_alert(args)

def acknowledge_alert(args):
    headers = { "Content-Type" : "application/json" }
    if args.ackUntil=="XXX":
        now = datetime.datetime.now()
        diff = datetime.timedelta(days=100*365)
        forever = now + diff
        args.ackUntil = forever.strftime("%Y-%m-%dT%H:%M:%SZ")
    ack_data = { "acknowledgedUntil" : args.ackUntil,
                 "acknowledgementComment" : args.ackComment }
    response = requests.patch(args.host
            +"/api/public/v1.0/groups/"
            +args.group+"/alerts/"+args.alertId
            ,auth=HTTPDigestAuth(args.username,args.apikey)
            ,headers=headers,
            data=json.dumps(ack_data))
    response.raise_for_status()
    result = json.dumps(response.json())
    print(result)

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
    host = args.host
    group_id = args.group
    user_name = args.username
    api_key = args.apikey
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
parser.add_argument("--ackAlert",dest='action', action='store_const'
        ,const=acknowledge_alert
        ,help='acknowledge an alert')
parser.add_argument("--processAlerts",dest='action', action='store_const'
        ,const=process_alerts
        ,help='custom processing and acknowlegment of alerts')
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
parser.add_argument("--createRestoreAndDeploy",dest='action', action='store_const'
        ,const=create_restore_and_deploy
        ,help='create a restore job from a given --clusterId for a given --snapshotId'+
        ' (or --snapshotTimestamp, --snapshotIncrement is optional)'
        ', download and unpack it, then deploy data in --restoreNamespace to --targetHost\n'+
        'NOTE: you must have the same or higher version of Mongo binaries installed on the machine '+
        'running this script as running on the --targetHost!')
parser.add_argument("--getAutomationConfig", dest='action', action='store_const'
        ,const=get_automation_config
        ,help='get the current automation state of all hosts in the group')
parser.add_argument("--setAutomationConfig", dest='action', action='store_const'
        ,const=set_automation_config
        ,help='update automation configuration through API endpoint')
parser.add_argument("--newAutomationConfigPath"
        ,help='path to file with new configuration for automation')
parser.add_argument("--targetHost"
        ,help='target OpsMgr/MongoDB host with protocol and port')
parser.add_argument("--targetGroup"
        ,help='target OpsMgr group id')
parser.add_argument("--targetUsername"
        ,help='target OpsMgr/MongoDB host user name')
parser.add_argument("--targetApikey"
        ,help='target OpsMgr api key for target user')
parser.add_argument("--targetPassword"
        ,help='target MongoDB instance password for target user')
parser.add_argument("--targetAuthenticationDatabase"
        ,help='target MongoDB instance authentication database target user')
parser.add_argument("--targetAuthenticationMechanism"
        ,help='target MongoDB instance authentication mechanism target user')
parser.add_argument("--alertConfigsSource"
        ,help='A file containing JSON alert configs or "-" for STDIN')
parser.add_argument("--clusterId"
        ,help='id of replica set or sharded cluster for snapshots')
parser.add_argument("--snapshotId"
        ,help='id of a snapshot to restore')
parser.add_argument("--snapshotTimestamp"
        ,help='point-in-time restore timestamp, format 2014-07-09T09:20:00Z')
parser.add_argument("--snapshotIncrement"
        ,help='point-in-time restore increment, a positive integer')
parser.add_argument("--restoreNamespace"
        ,help='Namespace(s) to restore from snapshot. Use "*" for all databases. '+
        'Use "foo.*" for all collections in the foo database. Use "foo.bar" for just the bar '+
        'collection in the foo database.')
parser.add_argument("--outDirectory"
        ,help='optional directory to save downloaded snapshot')
parser.add_argument("--restoreAndDeployTempPort"
        ,help='optional port number to run temporary mongod to restore snapshot from, '+
        'default is 27229',default='27229')
parser.add_argument("--restoreAndDeployTempMongodArgs"
        ,help='optional arguments for temp mongod to restore snapshot from.')
parser.add_argument("--restoreAndDeployDropFromTarget", action='store_true', default=False
        ,help='optional arguments for mongorestore process used to restore snapshot to --targetHost.' +
        ' For example "--drop" to force a drop of the collection(s) to be restored.')
parser.add_argument("--continueOnError", action='store_true', default=False
        ,help='for operations that issue multiple API calls, set this flag to fail to report errors but keep going')
parser.add_argument("--verbose", action='store_true', default=False
        ,help='enable versbose output for troubleshooting')
parser.add_argument("--format", default='json'
        ,help='specify output format')
parser.add_argument("--alertId"
        ,help="id of alert to acknowledge")
parser.add_argument("--ackUntil", default="XXX"
        ,help="datetime to ack alert default is 'forever' (100 years in the future)")
parser.add_argument("--ackComment"
        ,help="comment to add for alert ack")

parsed_args = parser.parse_args()

vprint( vars(parsed_args), parsed_args )

if parsed_args.action is None:
    parser.parse_args(['-h'])
else:
    parsed_args.action(parsed_args)
