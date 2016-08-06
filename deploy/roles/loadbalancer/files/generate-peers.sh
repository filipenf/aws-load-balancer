#!/bin/bash
# just a quick-and-dirty solution to update the peers configuration of haproxy upon ASG changes
# instance-id becomes the peer name ( need to use -L<instance_id> on the haproxy command line)
# port 7777 is used for p2p communication
# call this script on crontab and redirect the output to > /etc/haproxy/peers.cfg then include that file into your haproxy config

instance_id=$(curl http://169.254.169.254/latest/meta-data/instance-id)
region=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone/)
region=${region:0:${#region}-1}

asg_name=$(aws ec2 describe-instances --instance-ids $instance_id --region $region | jq '.Reservations[].Instances[].Tags[] | select(.Key=="aws:autoscaling:groupName") | .Value' | xargs)
instances=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name $asg_name --region $region --query "AutoScalingGroups[].Instances[].InstanceId" --output text | xargs )
private_ips=$(aws ec2 describe-instances --instance-ids $instances --region $region --query 'Reservations[].Instances[][InstanceId,NetworkInterfaces[].PrivateIpAddresses[0].PrivateIpAddress]' --output text | xargs -I{} echo -n "{};")
IFS=";" read -a results <<< "$private_ips"

echo "peers lb_replication"
for (( i=0; i<$(( ${#results[@]} / 2 )); i++ )); do
  id=${results[$((i*2))]}
  ip=${results[$((1+i*2))]}
  echo "    peer $id $ip:7777"
done

