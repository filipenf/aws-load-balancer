import boto3
import uuid
import json
import sys
import traceback

def get_asg(asg_name, region):
    print "looking for %s in region %s" % (asg_name, region)
    autoscale = boto3.client('autoscaling', region_name=region)
    groups = autoscale.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    if len(groups['AutoScalingGroups']) < 1:
        raise Exception("No auto-scaling group named %s found" % asg_name)
    return groups['AutoScalingGroups'][0]

def get_asg_domain(asg):
    for tag in asg['Tags']:
        if tag['Key'] == "domain":
            return tag['Value']
    return None

def get_ips_from_asg(asg, region):
    ec2 = boto3.client('ec2', region_name=region)
    instance_ids = [i['InstanceId'] for i in asg['Instances']]
    if len(instance_ids) == 0:
        print "WARNING: No instances in autoscaling group"
        return []
    else:
        reservations = ec2.describe_instances(InstanceIds=instance_ids)['Reservations']
        instances = dict()
        for r in reservations:
            for i in r['Instances']:
                if i.has_key('PublicIpAddress'):
                    instances[i['InstanceId']] = i['PublicIpAddress']
        print "ASG Instances' IP addresses: [ %s ]" % json.dumps(instances)
        return instances

def get_existing_health_checks(ips, region):
    conn = boto3.client('route53', region_name=region)
    ip_to_hc = {}
    hc_list = conn.list_health_checks()
    while hc_list:
        for hc in hc_list['HealthChecks']:
            ip = hc['HealthCheckConfig']['IPAddress']
            if ip in ips:
                ip_to_hc[ip] = hc['Id']
        if hc_list.has_key('NextMarker'):
            hc_list = conn.list_health_checks(hc_list['NextMarker'])
        else:
            break

    return ip_to_hc

def delete_health_checks(ips, existing_health_checks, region):
    conn = boto3.client('route53', region_name=region)
    for ip in ips:
        if existing_health_checks.has_key(ip):
            conn.delete_health_check(HealthCheckId=existing_health_checks[ip])

def create_health_check_for_ip(fqdn, ip, region):
    config = {
        'IPAddress': ip,
        'Port': 443,
        'Type': 'TCP',
        'RequestInterval': 30,
        'FailureThreshold': 2,
        'MeasureLatency': False,
        'Inverted': False,
        'ChildHealthChecks': [],
        'EnableSNI': False,
    }
    print "Creating health check for ip %s" % ip
    conn = boto3.client('route53', region_name=region)
    response = conn.create_health_check(
            CallerReference=str(uuid.uuid1()),
            HealthCheckConfig=config)
    print response
    return response['HealthCheck']['Id']

def sync_records(fqdn, ips, region=None):
    def delete_rr(r):
        return { "Action": "DELETE", "ResourceRecordSet": r }

    def create_rr(ip, existing_health_checks):
        health_check_id = existing_health_checks.get(ip, None)
        if health_check_id is None:
            health_check_id = create_health_check_for_ip(fqdn, ip, region)
        return {
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": fqdn,
                "Type": "A",
                "TTL": 60,
                "SetIdentifier": ip,
                "Weight": 1,
                "ResourceRecords": [ { 'Value': ip } ],
                "HealthCheckId": health_check_id
            }
        }

    r53conn = boto3.client('route53', region_name=region)
    domain = fqdn[fqdn.find('.')+1:]
    zone = [zone for zone in r53conn.list_hosted_zones()['HostedZones']
            if zone['Name']==domain+"."][0]
    if not zone:
        raise Exception("Unable to find domain %s" % domain)

    zone_id = zone['Id'].split('/')[2]
    zone_records = r53conn.list_resource_record_sets(HostedZoneId=zone_id, StartRecordName=fqdn)['ResourceRecordSets']
    existing_records = {}
    for r in zone_records:
        if not r['Name'].startswith(fqdn):
            continue
        for ip in r['ResourceRecords']:
            existing_records[ip['Value']] = r
    print "Existing IPs on route53 for domain %s: [ %s ]" % (fqdn, json.dumps(existing_records))
    existing_ips = set(existing_records.viewkeys())

    existing_health_checks = get_existing_health_checks(existing_ips.union(ips), region)

    changes = []
    to_delete = existing_ips - set(ips)
    print "Deleting IPs: [ %s ] from route53" % ", ".join(to_delete)
    for ip in to_delete:
        changes.append(delete_rr(existing_records[ip]))

    to_add = set(ips) - existing_ips
    print "Adding IPs: [ %s ] to route53" % ", ".join(to_add)
    for ip in to_add:
        changes.append(create_rr(ip, existing_health_checks))

    if len(to_add) > 0 or len(to_delete) > 0:
        delete_health_checks(to_delete, existing_health_checks, region)
        print "Changes = "+json.dumps(changes)
        r53conn.change_resource_record_sets(
                HostedZoneId = zone_id,
                ChangeBatch = {
                    "Comment": "Updated by lambda",
                    "Changes": changes
                })
        print "Route53 changes applied successfully"
    else:
        print "Route53 records already in-sync"

def lambda_handler(event, context):
    message = json.loads(event['Records'][0]['Sns']['Message'])
    metadata = json.loads(message['NotificationMetadata'])
    asg_name = message['AutoScalingGroupName']
    region = metadata['region']

    print "Route53 update for %s - region %s" % (asg_name, region)

    asg = get_asg(asg_name, region)
    fqdn = get_asg_domain(asg)

    try:
        if fqdn is not None:
            ip_map = get_ips_from_asg(asg, region)
            print ip_map
            if message['LifecycleTransition'] == "autoscaling:EC2_INSTANCE_TERMINATING":
                ip_map.pop(message['EC2InstanceId'], None)
            sync_records(fqdn, ip_map.values(), region)
        else:
            print "Autoscaling group %s doesn't have a 'domain' tag. Skipping" % asg_name
    except:
        t, v, tb = sys.exc_info()
        traceback.print_exception(t, v, tb)

    print "Completing lifecycle action for ASG %s" % asg_name

    autoscale = boto3.client('autoscaling', region_name=region)
    autoscale.complete_lifecycle_action(
        LifecycleHookName=message['LifecycleHookName'],
        AutoScalingGroupName=asg_name,
        LifecycleActionToken=message['LifecycleActionToken'],
        LifecycleActionResult='CONTINUE')
