#import statements

import argparse
import boto3
import os
import sys
from pathlib import Path
from slackclient import SlackClient

#regionsCode

regions=['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-west-2','eu-west-3',
         'ca-central-1','eu-central-1','ap-northeast-1','ap-northeast-2','ap-southeast-1',
         'ap-southeast-2','ap-south-1','sa-east-1'];


#regionsName

regionsName=['US East\n(N. Virginia)','US East (Ohio)','US West \n(N.California)','US West (Oregon)','EU (Ireland)','EU (London)','EU (Paris)',
         'Canada (Central)','EU (Frankfurt)','Asia Pacific\n(Tokyo)','Asia Pacific\n(Seoul)','Asia Pacific\n(Singapore)',
         'Asia Pacific\n(Sydney)','Asia Pacific\n(Mumbai)','South America\n(São Paulo)'];



total=0;
#userName=os.getenv('username');
home=Path.home();


zonetag=[];
zoneuntag=[];
tagged=[];
untagged=[];
ass_elastic_Ip=[]
unass_elastic_Ip=[];
attached_volume=[];
unattached_volume=[];
#methods

def insLimit(token): #Instance Limit
    count=0;
    inscount=0;
    max_limit=0;
    totalins=0;
    limit=connect.describe_account_attributes(AttributeNames=['max-instances']);
    for ins in limit['AccountAttributes']:
        max_limit=ins['AttributeValues'][0]['AttributeValue'];# Max limit of instance in region
        count=int(max_limit)-2;
    zone=connect.describe_availability_zones()
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]        
        inst=connect.describe_instances(); 
        inscount=len(inst['Reservations']); #count the instances in region
    if int(inscount)>=count:#Checks insatcnes count reached the maximum limit
        slack_token = token;
        sc=SlackClient(slack_token);
        s=sc.api_call('chat.postMessage',channel='#general',text="WARNING:\nYour Instance is going to exceeded\n\nCurrentInstanceCount: "+str(inscount)+"\n\nRegion :"+regionsName[i]);#Send message to slack channel

def addToken():#add token
    path=str(home)+"\\.ResourceMonitor\\";
    if not os.path.exists(path):
        os.mkdir(path);
    cf=open(path+"token","wb+")
    send=args.token
    cf.write(send.encode())
    cf.close();
def changeToken(): #changetoken
    path=str(home)+"\\.ResourceMonitor\\";
    cf=open(path+"token","wb+")
    send=args.token
    cf.write(send.encode())
    cf.close();
    print("updated");



def els(): # Elastic Ips 
    zone=connect.describe_availability_zones();
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]
        el=connect.describe_addresses()
        
        for ip in el['Addresses']:
            if "InstanceId" in ip:
                ass_elastic_Ip.append(ip['PublicIp'])
                zonetag.append(zname)
            else:
                unass_elastic_Ip.append(ip['PublicIp'])
                zoneuntag.append(zname)
            if (( ip['PublicIp'] in ass_elastic_Ip and ip['PublicIp'] in unass_elastic_Ip ) or (ass_elastic_Ip.count(ip['PublicIp'])>1)):
                    ass_elastic_Ip .remove(ip['PublicIp'])
            for ni in range(len(ass_elastic_Ip)):
                if ass_elastic_Ip[ni] in unass_elastic_Ip:
                    ass_elastic_Ip.remove(ass_elastic_Ip[ni]);
            if ((unass_elastic_Ip.count(ip['PublicIp'])>1)):
                unass_elastic_Ip .remove(ip['PublicIp']);


def Volume(getNum):    
    zone=connect.describe_availability_zones();
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]
        if getNum == 0:
            vol=connects.volumes.filter(Filters=[{'Name':'status','Values':['in-use']},{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t"+volu.volume_type)
                for att in volu.attachments:
                    print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+att['InstanceId'])
        if getNum == 1:
            vol=connects.volumes.filter(Filters=[{'Name':'status','Values':['available']},{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t"+volu.volume_type)
        if getNum == 2:
            vol=connects.volumes.filter(Filters=[{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                #print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t"+volu.volume_type)
                for att in volu.attachments:
                    if "InstanceId" in att:
                        attached_volume.append(volu.id)
                        zonetag.append(zname)
                    else:
                        unattached_volume.append(volu.id)
                        zoneuntag.append(zname)
                if (( volu.id in attached_volume and volu.id in unattached_volume ) or (attached_volume.count(volu.id)>1)):
                    attached .remove(volu.id)
                for ni in range(len(attached_volume)):
                    if attached_volume[ni] in unattached_volume:
                        attached_volume.remove(attached_volume[ni]);
                if ((unattached_volume.count(volu.id)>1)):
                    ununattached_volume .remove(volu.id);



def StatusInstances(input): #instances state (running,stopped,terminated)
    try:
        count=0;
        zone=connect.describe_availability_zones();
        for zones in zone['AvailabilityZones']:
            zname=zones["ZoneName"]
            getStaIns=connects.instances.filter(Filters=[
            {
                'Name':'instance-state-name',
                'Values':[input]
                },
            {
                'Name':'availability-zone',
                'Values':[zname]
                }
            ]
                                            );
            for staIns in getStaIns:
                print(regionsName[i]+"\t"+zname+"\t"+staIns.instance_type+"\t\t"+staIns.id+"\t"+staIns.public_ip_address+"\t\t\t"+staIns.key_name);
                count=count+1;
        if count >=1:
            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+str(count)+" "+input);
            total=count;
    except:
        print("");



def filterByTag(getNum): #filter by tags
    zone=connect.describe_availability_zones();
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]
        getStaIns=connects.instances.filter(Filters=[
        {
            'Name':'instance-state-name',
            'Values':['running','stopped','terminated']
            },
        {
            'Name':'availability-zone',
            'Values':[zname]
            }
        ]
                                        );
        if getNum == 0: #all [tagged and untagged]
            for ins in getStaIns:
                if ins.tags:
                    print(regionsName[i]+"\t"+zname+"\t"+ins.instance_type+"\t\t"+ins.id+"\t"+ins.public_ip_address+"\t\t\t"+ins.key_name+"\t\tTAGGED");
                else:
                    print("\n\n"+regionsName[i]+"\t"+zname+"\t"+ins.instance_type+"\t\t"+ins.id+"\t"+ins.public_ip_address+"\t\t\t"+ins.key_name+"\t\tUNTAGGED");
        if getNum == 1: #tagged
            for ins in getStaIns:
                if ins.tags:
                    print("\n\n"+regionsName[i]+"\t"+zname+"\t"+ins.instance_type+"\t\t"+ins.id+"\t"+ins.public_ip_address);
                    for tag in ins.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+tag['Key']+"\t\t\t"+tag['Value']);

        if getNum == 2: #untagged
            for ins in getStaIns:
                if not ins.tags:
                    print("\n\n"+regionsName[i]+"\t"+zname+"\t"+ins.instance_type+"\t\t"+ins.id+"\t"+ins.public_ip_address);
        if getNum == 3:
            for ins in getStaIns:
                if ins.tags:
                     taggs=[];
        
                     tagcount=len(ins.tags);
                     for n in range(tagcount):
                         taggs.append((ins.tags[n]['Key']))
                     t=[ni.lower() for ni in taggs[:]];
                     l=[ni.lower() for ni in args.filter[:]];
                     for r in range(len(args.filter)):
                         if l[r] in t:
                             tagged.append(ins.id);
                             zonetag.append(zname)
                         else:
                             untagged.append(ins.id);
                             zoneuntag.append(zname);
                else:
                    
                    untagged.append(ins.id);
                    zoneuntag.append(zname);
                if (( ins.id in tagged and ins.id in untagged) or (tagged.count(ins.id)>1)):
                    tagged.remove(ins.id)
                for ni in range(len(tagged)):
                    if tagged[ni] in untagged:
                        tagged.remove(tagged[ni]);
                if ((untagged.count(ins.id)>1)):
                    untagged.remove(ins.id);



def configure(): #creating configuration files
    path=str(home)+"\\.aws\\";
    accessKey=input("Enter the AWS ACCESS KEY ID:");
    secretKey=input("Enter the AWS SECRET ACCESS KEY:");
    if not os.path.exists(path):
        os.mkdir(path);
    createFile=open(path+"credentials"+"wb+");
    send="[default]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"";
    createFile.write(send.encode());
    backupFile=open(path+".bak"+"wb+");
    backupFile.write(send.encode());
    print("\nConfig file updated.\n");


def checkConfig(): #checking for configuration files 
    access=0;
    path=str(home)+"\\.aws\\";
    if not os.path.exists(path):
        access=access+1;
    return access;


def createProfile(): #create new profile
    profilename=input("PROFILE NAME: ");
    accessKey=input("AWS ACCESS KEY ID: ");
    secretKey=input("AWS SECRET ACCESS KEY: ");
    path=str(home)+"\\.ResourceMonitor\\";
    if not os.path.exists(path):
        os.mkdir(path);
    createProfile=open(path+profilename,"wb+");
    send="[default]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"";
    createProfile.write(send.encode());
    print("\nProfile created successfully.\n");


def restore(): #restoring the backup file
    path=str(home)+"\\.aws\\";
    backupFile=open(path+".bak","r");
    createFile=open(path+"credentials","wb+");
    default=backupFile.read();
    createFile.write(default.encode());
    
    


def profile(paths): #change profile
    path=str(home)+"\\.aws\\";
    if not os.path.exists(path):
        os.mkdir(path);
    openFile=open(str(home)+"\\.ResourceMonitor\\"+paths,"r");
    fileText=openFile.read();
    sendFile=open(path+"credentials","wb+");
    sendText=sendFile.write(fileText.encode());
    print("\nprofile changed.\n");

def deleteProfile(profileName): #delete profile
    os.remove(str(home)+"\\.ResourceMonitor\\"+profileName);
    print("\nProfile deleted successfully");

#argument parser

parser=argparse.ArgumentParser(description="Resource Monitor - AWS EC2",formatter_class=argparse.RawTextHelpFormatter,usage="[-h] [--region REGION] [--filter NAMES][--token TOKEN] [--profile PROFILE] options");

parser.add_argument("options",help="instance state [ running | stopped | terminated | all ] \ntags [ tagged | untagged | tags ]\nconfiguration [ configure | createprofile | deleteprofile ]\nlimit\ntoken[ addtokoen | changetoken ]\nvolume [ all-volume | attached-volume | unattached-volume ]\nelastic-ip"
                    "\n\n[instance state]\n\nrunning = display all running instances\nstopped = display all stopped instances\nterminated = display all terminated instances"
                    "\nall = diplay all instances"
                    "\n\n[tags]\n\ntagged = display all tagged instances\nuntagged = display all untagged instances\ntags = display all tagged and untagged instances\n\n[Configuration]\n\nconfigure = configure authentication keys\ncreateprofile = create new profile"
                    "\ndeleteprofile = delete the created profile\n\n[ Config file location : C:\\Users\\..\\.ResourceMonitor ]"
                    "\n\nlimit = Check the instance limit"
                    "\n\n[volume] \n\nall-volume = display both attached and unattached volumes\nattached-volume = display only in-use volumes\nunattached-volume = disply only unattached volumes"
                    "\n\nelastic-ip = Display attached and unattached elastic Ips"
                    "\n[token]\naddtoken = add slack api token tto send message\changetoken = change the slack api token ");
parser.add_argument("--region",help="Regions");

parser.add_argument("--filter",nargs='*',help="Filter Instance with Specific tags ");
parser.add_argument("--token",help="SlackToken");
parser.add_argument("--profile",help="Profile Name");

get=checkConfig();
args=parser.parse_args();

if args.options=="configure": #configure authentication keys
    configure();

elif args.options=="createprofile": #create new profile
    createProfile();

elif args.options=="deleteprofile": #delete profile
    profileName=input("PROFILE NAME: ");
    deleteProfile(profileName);

elif not get==0: #checking config files
    print("No config file detected. type > monitor configure");
    sys.exit();



#action for arguments

if args.options=="running":  #running
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        i=regions.index(args.region);
        StatusInstances("running");
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            StatusInstances("running");


if args.options=="stopped": #stopped
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        i=regions.index(args.region);
        StatusInstances("stopped");
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            StatusInstances("stopped");


if args.options=="terminated": #terminated
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        i=regions.index(args.region);
        StatusInstances("terminated");
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            StatusInstances("terminated");



if args.options=="all": #all [running,stopped,terminated]
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        i=regions.index(args.region);
        StatusInstances("running");
        StatusInstances("stopped");
        StatusInstances("terminated");
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY PAIR NAME\t\tTOTAL\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            StatusInstances("running");
            StatusInstances("stopped");
            StatusInstances("terminated");

if args.options=="tagged": #tagged
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        filterByTag(1);
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(1);


if args.options=="untagged": #untagged
    if args.profile:
        profile(args.profile);
    if args.region:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        filterByTag(2);
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(2);

if args.options=="tags": #tags[tagged and untagged]
    if args.profile:
        profile(args.profile);
    if args.region:
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        if args.filter:
            filterByTag(3);
            print("\n")
            print("\n\t\t\t'TAGGED INSTANCES'")
            print("\n")
            print("\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
            for ni in range(len(tagged)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[tagged[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n"+regionsName[i]+"\t\t"+zonetag[ni]+"\t\t"+inst.instance_type+"\t\t"+inst.id+"\t"+inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+tag['Key']+"\t\t"+tag['Value'])
            print("\n")
            print("\n\t\t\t'UNTAGGED INSTANCES'")
            print("\n")
            print("\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
            for ni in range(len(untagged)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[untagged[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n"+regionsName[i]+"\t\t"+zoneuntag[ni]+"\t\t"+inst.instance_type,"\t\t"+inst.id+"\t",inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+tag['Key']+"\t\t"+tag['Value'])
            
                    
        else:
            print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
            filterByTag(0);
    elif args.filter:
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(3);
        print("\n")
        print("\n\t\t\t'TAGGED INSTANCES'")
        print("\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
        print("\n")
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            for ni in range(len(tagged)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[tagged[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n"+regionsName[i]+"\t\t"+zonetag[ni]+"\t\t"+inst.instance_type+"\t\t"+inst.id+"\t"+inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+tag['Key']+"\t\t"+tag['Value'])
        print("\n\n")
        print("\n\t\t\t'UNTAGGED INSTANCES'")
        print("\n")
        print("\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            for ni in range(len(untagged)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[untagged[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n",regionsName[i]+"\t\t"+zoneuntag[ni]+"\t\t"+inst.instance_type+"\t\t"+inst.id+"\t\t"+inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+tag['Key']+"\t\t"+tag['Value'])

    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(0);

if args.options=="attached-volume":
    if args.region:
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID")
        print("\n")
        Volume(0);     
    else:
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID")
        print("\n")
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            Volume(0);
if args.options=="unattached-volume":
    if args.region:
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE")
        print("\n")
        Volume(1);     
    else:
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE")
        print("\n")
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            Volume(1);
if args.options=="all-volume":
    if args.region:
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        Volume(2);
        print("\n\n\t\tAttached Volumes\n")
        if len(attached_volume) == 0:
            print("No Attached Volumes")
        else:
            print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID")
            print("\n")
            for volume in range(len(attached_volume)):
                vol=connects.volumes.filter(Filters=[{'Name':'volume-id','Values':[attached_volume[volume]]}])
                for volu in vol:
                    print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t\t"+volu.volume_type)
                for att in volu.attachments:
                    print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+att['InstanceId'])
        print("\n\n\t\tUnAttached Volumes\n")
        if len(unattached_volume) == 0:
            print("No Unattached volumes")
        else:
            print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE")
            print("\n")
            for volume in range(len(unattached_volume)):
                vol=connects.volumes.filter(Filters=[{'Name':'volume-id','Values':[unattached_volume[volume]]}])
                for volu in vol:
                    print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t\t"+volu.volume_type)
                
        
        
        
    else:
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            Volume(2);
        print("\n\n\t\tAttached Volumes\n")
        if len(attached_volume) == 0:
            print("No Attached Volumes")
        else:
            print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID\n")
            for i in range(0,10):
                connects=boto3.resource('ec2',regions[i]);
                connect=boto3.client('ec2',regions[i]);
                for volume in range(len(attached_volume)):
                    vol=connects.volumes.filter(Filters=[{'Name':'volume-id','Values':[attached_volume[volume]]}])
                    for volu in vol:
                        print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t\t"+volu.volume_type)
                        for att in volu.attachments:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"+att['InstanceId'])
        print("\n\n\t\tUnAttachedVolumes\n");
        if len(unattached_volume) == 0:
            print("No UnAttached Volumes")
        else:
            print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\n")
            for i in range(0,10):
                connects=boto3.resource('ec2',regions[i]);
                connect=boto3.client('ec2',regions[i]);
                for volume in range(len(unattached_volume)):
                    vol=connects.volumes.filter(Filters=[{'Name':'volume-id','Values':[unattached_volume[volume]]}])
                    for volu in vol:
                        print(regionsName[i]+"\t"+volu.availability_zone+"\t\t    "+volu.id+"\t"+volu.state+"\t\t\t"+volu.volume_type)
                



if args.options=="limit":#intance limit
    if args.profile:
        profile(args.profile);
    path=str(home)+"\\.ResourceMonitor\\token";
    if os.path.exists(path):
        print("")
        if args.region:
            path=str(home)+"\\.ResourceMonitor\\token";
            read=open(path,'r').read();
            print("Checking Instance Limit in "+args.region+".....")
            i=regions.index(args.region);
            connects=boto3.resource('ec2',args.region);
            connect=boto3.client('ec2',args.region);
            insLimit(read);
            print("Completed successfully");
        else:
            path=str(home)+"\\.ResourceMonitor\\token";
            read=open(path,'r').read();
            print("\n")
            print("Checking Instance Limit in all region.....")
            for i in range(0,10):
                connects=boto3.resource('ec2',regions[i]);
                connect=boto3.client('ec2',regions[i]);
                insLimit(read);
            print("Completed successfully");
    else:
        print("ERROR:Add Slack API token using addtoken --token yourtoken")


if args.options == "elastic-ip":#associated and unassociated Volumes
    del zonetag[:];
    del zoneuntag[:];
    if args.region:
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        els();
        print("\n\n\t\tAssociated ElasticIps")
        if len(ass_elastic_Ip) == 0:
            print("\nNo Associated ElasticIps ")
        else:
            print("\n\nREGION\t\t\tAVAILABILITY-ZONE\tELASTIC-IP\tALLOCATION-ID\t\tASSOCIATED-INSTANCEID\t\tNETWORK INTERFACEID\tDOMAIN")
            for ip in range(len(ass_elastic_Ip)):
                els_ip=connect.describe_addresses(Filters=[{'Name':'public-ip','Values':[ass_elastic_Ip[ip]]}])
                for elasticip in els_ip['Addresses']:
                    print("\n\n"+regionsName[i]+"\t"+zonetag[ip]+"\t\t"+elasticip['PublicIp']+"\t"+elasticip['AllocationId']+"\t"+elasticip['InstanceId']+"\t\t"+elsasticip['NetworkInterfaceId']+"\t\t",elasticip['Domain'])
        print("\n\n\t\tUnAssociated ElasticIps")
        if len(unass_elastic_Ip) == 0:
            print("\nNo UnAssociated ElasticIps ")
        else:
            print("\n\nREGION\t\t\tAVAILABILITY-ZONE\t\tELASTIC-IP\t\tALLOCATION-ID\t\t\tDOMAIN")
            for ip in range(len(unass_elastic_Ip)):
                els_ip=connect.describe_addresses(Filters=[{'Name':'public-ip','Values':[unass_elastic_Ip[ip]]}])
                for elasticip in els_ip['Addresses']:
                    print("\n\n"+regionsName[i]+"\t"+zoneuntag[ip]+"\t\t\t"+elasticip['PublicIp']+"\t\t"+elasticip['AllocationId']+"\t\t"+elasticip['Domain'])
    else:
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            els();
        print("\n\n\t\tAssociated ElasticIps")
        if len(ass_elastic_Ip) == 0:
            print("\nNo Associated ElasticIps ")
        else:
            print("\n\nREGION\t\t\tAVAILABILITY-ZONE\tELASTIC-IP\tALLOCATION-ID\t\tASSOCIATED-INSTANCEID\t\tNETWORK INTERFACEID\tDOMAIN")
            for i in range(0,10):
                connects=boto3.resource('ec2',regions[i]);
                connect=boto3.client('ec2',regions[i]);
                for ip in range(len(ass_elastic_Ip)):
                    els_ip=connect.describe_addresses(Filters=[{'Name':'public-ip','Values':[ass_elastic_Ip[ip]]}])
                    for elasticip in els_ip['Addresses']:
                        print("\n\n"+regionsName[i]+"\t"+zonetag[ip]+"\t\t"+elasticip['PublicIp']+"\t"+elasticip['AllocationId']+"\t"+elasticip['InstanceId']+"\t\t"+elasticip['NetworkInterfaceId']+"\t\t"+elasticip['Domain'])
        print("\n\n\t\tUnAssociated ElasticIps")
        if len(unass_elastic_Ip) == 0:
            print("\nNo UnAssociated ElasticIps")
        else:
            print("\n\nREGION\t\t\tAVAILABILITY-ZONE\t\tELASTIC-IP\t\tALLOCATION-ID\t\t\tDOMAIN")
            for i in range(0,10):
                connects=boto3.resource('ec2',regions[i]);
                connect=boto3.client('ec2',regions[i]);
                for ip in range(len(unass_elastic_Ip)):
                    els_ip=connect.describe_addresses(Filters=[{'Name':'public-ip','Values':[unass_elastic_Ip[ip]]}])
                    for elasticip in els_ip['Addresses']:
                        print("\n\n"+regionsName[i]+"\t"+zoneuntag[ip]+"\t\t\t"+elasticip['PublicIp']+"\t\t"+elasticip['AllocationId']+"\t\t"+elasticip['Domain'])


if args.options=="addtoken":
    addToken();

if args.options=="updatetoken":
    changeToken();



restore();
