#!/usr/bin/env python
#
# opsmtools.py - expose various MongoDB
# Ops Manager API endpoint through a simple
# command line script.
#
# Installation:
# pip install requests,terminaltables
#
import argparse
import requests
import json
import copy
from requests.auth import HTTPDigestAuth


# verbose print message only if args.verbose=True
def vprint(message,args):
    if args.verbose==True:
        print message

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

    alerts_json = response.json()

    table_data = [
        ['eventTypeName','status','created','replicaSetName']
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

    alert_configs = response.json()
    print(alert_configs)


def delete_alert_configs(args):
    print('delete_alert_configs')
    print( vars(args) )

def migrate_alert_configs(args):
    print('migrate_alert_configs');
    print( vars(args) )
    response = requests.get(args.host+
            "/api/public/v1.0/groups/"+args.group+"/alertConfigs"
            ,auth=HTTPDigestAuth(args.username,args.apikey))
    response.raise_for_status()
    alert_configs = response.json()
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
        #url = "http://requestb.in/15ftkhl1"
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

parser.add_argument("--getAlerts",dest='action', action='store_const'
        ,const=get_alerts
        ,help='get alerts')
parser.add_argument("--getAlertConfigs",dest='action', action='store_const'
        ,const=get_alert_configs
        ,help='get alert configurations')
parser.add_argument("--deleteAlertConfigs",dest='action', action='store_const'
        ,const=delete_alert_configs
        ,help='delete ALL alert configs from host')
parser.add_argument("--migrateAlertConfigs",dest='action', action='store_const'
        ,const=migrate_alert_configs
        ,help='migrate ALL alert configs from host to target')
parser.add_argument("--targetHost"
        ,help='target OpsMgr host with protocol and port')
parser.add_argument("--targetGroup"
        ,help='target OpsMgr group id')
parser.add_argument("--targetUsername"
        ,help='target OpsMgr host user name')
parser.add_argument("--targetApikey"
        ,help='target OpsMgr api key for target user')
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
