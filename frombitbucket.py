import argparse
import boto3
import os
import sys
from pathlib import Path
from slackclient import SlackClient;
import colorama

from colorama import Fore, Back, Style
colorama.init()
#regionsCode

regions=['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-west-2','eu-west-3',
         'ca-central-1','eu-central-1','ap-northeast-1','ap-northeast-2','ap-southeast-1',
         'ap-southeast-2','ap-south-1','sa-east-1'];

#regions
#regionsName

regionsName=['US East\n(N. Virginia)\t','US East (Ohio)','US West \n(N.California)\t','US West (Oregon)','EU (Ireland)','EU (London)','EU (Paris)',
         'Canada (Central)','EU (Frankfurt)','Asia Pacific\n(Tokyo)','Asia Pacific\n(Seoul)','Asia Pacific\n(Singapore)',
         'Asia Pacific\n(Sydney)','Asia Pacific\n(Mumbai)','South America\n(São Paulo)'];



total=0;
#userName=os.getenv('username');
home=Path.home();

zt=[];
zu=[];
b=[];
c=[];
print("\n")

#methods

def insLimit(token): #Instance Limit in alla region and specific region
    count=0;
    inscount=0;
    max_limit=0;
    zone=connect.describe_availability_zones()
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]        
        limit=connect.describe_account_attributes(AttributeNames=['max-instances']);
        inst=connect.describe_instances(); 
        inscount=len(inst['Reservations']); #count the instances in region
        for ins in limit['AccountAttributes']:
            max_limit=ins['AttributeValues'][0]['AttributeValue'];# Max limit of instance in region
            count=int(max_limit)-2;
    if int(inscount)>=count:#Checks insatcnes count reached the maximum limit
        slack_token = token;
        sc=SlackClient(slack_token);
        s=sc.api_call('chat.postMessage',channel='#general',text="WARNING:\nYour Instance is going to exceeded\n\nCurrentInstanceCount: "+str(inscount)+"\n\nRegion :"+regionsName[i]);#Send message to slack channel

def addToken():#add token
    path=str(home)+"\\.ResourceMonitor\\";
    if not os.path.exists(path):
        os.mkdir(path);
    cf=open(path+"token","wb+")
    
    send="\n "+args.token
    cf.write(send.encode())
    cf.close();
def changeToken(): #changetoken
    path=str(home)+"\\.ResourceMonitor\\";
    cf=open(path+"token","wb+")
    send="\n "+args.token
    cf.write(send.encode())
    cf.close();
    print("updated");


def Volume(getNum):    
    zone=connect.describe_availability_zones();
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]
        if getNum == 0:
            vol=connects.volumes.filter(Filters=[{'Name':'status','Values':['in-use']},{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                print(regionsName[i],"\t",volu.availability_zone,"\t\t    ",volu.id,"\t",volu.state,"\t\t",volu.volume_type)
                for att in volu.attachments:
                    print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",att['InstanceId'])
        if getNum == 1:
            vol=connects.volumes.filter(Filters=[{'Name':'status','Values':['available']},{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                print(regionsName[i],"\t",volu.availability_zone,"\t\t    ",volu.id,"\t",volu.state,"\t\t",volu.volume_type)
        if getNum == 2:
            vol=connects.volumes.filter(Filters=[{'Name':'availability-zone','Values':[zname]}])
            for volu in vol:
                print(regionsName[i],"\t",volu.availability_zone,"\t\t    ",volu.id,"\t",volu.state,"\t\t",volu.volume_type)
                for att in volu.attachments:
                    print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",att['InstanceId'])
            
            
        
                                     

def notAttVolume():
    zone=connect.describe_availability_zones();
    for zones in zone['AvailabilityZones']:
        zname=zones["ZoneName"]
        vol=connects.volumes.filter(Filters=[{'Name':'status','Values':['available']},{'Name':'availability-zone','Values':[zname]}])
        for volu in vol:
            print(regionsName[i],"\t",volu.availability_zone,"\t\t    ",volu.id,"\t",volu.state,"\t\t",volu.volume_type)
            for att in volu.attachments:
                print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",att['InstanceId'])


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


print("\n")
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
        ]);
                                     
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
                             b.append(ins.id);
                             zt.append(zname)
                         else:
                             c.append(ins.id);
                             zu.append(zname);
                else:
                    
                    c.append(ins.id);
                    zu.append(zname);
                if (( ins.id in b and ins.id in c) or (b.count(ins.id)>1)):
                    b.remove(ins.id)
                for ni in range(len(b)):
                    if b[ni] in c:
                        b.remove(b[ni]);
                if ((c.count(ins.id)>1)):
                    c.remove(ins.id);
                
            

    
               
def configure(): #creating configuration files
    path=str(home)+"\\.aws\\";
    accessKey=input("Enter the AWS ACCESS KEY ID:");
    secretKey=input("Enter the AWS SECRET ACCESS KEY:");
    if not os.path.exists(path):
        os.mkdir(path);
    createFile=open(path+"credentials","wb+");
    send="[default]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"";
    createFile.write(send.encode());
    backupFile=open(path+".bak","wb+");
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

parser=argparse.ArgumentParser(description="Resource Monitor - AWS EC2",formatter_class=argparse.RawTextHelpFormatter);

parser.add_argument("options",help="instance state [ running | stopped | terminated | all ] \ntags [ tagged | untagged | tags | tagkey ]\nconfiguration [ configure | createprofile | deleteprofile ]\nlimit\ntoken[ addtokoen | changetoken ]\nvolume [ all-volume | att-volume | un-att-volume ]"
                    "\n\n[instance state]\n\nrunning = display all running instances\nstopped = display all stopped instances\nterminated = display all terminated instances"
                    "\nall = diplay all instances"
                    "\n\n[tags]\n\ntagged = display all tagged instances\nuntagged = display all untagged instances\ntags = display all tagged and untagged instances\n\n[Configuration]\n\nconfigure = configure authentication keys\ncreateprofile = create new profile"
                    "\ndeleteprofile = delete the created profile\n\n[ Config file location : C:\\Users\\..\\.ResourceMonitor ]"
                    "\n\nlimit = Check the instance limit"
                    "\n\n[volume] \n\nall-volume = display all volume\natt-volume = display only in-use volume\nun-att-volume = disply only unattached volumes"
                    "\n[token]\naddtoken = add slack api token tto send message\changetoken = change the slack api token ");
parser.add_argument("--region",help="Regions");
parser.add_argument("--filter",nargs='*',help="Tag");
parser.add_argument("--token",help="SlackToken");
parser.add_argument("--profile",help="Profile Name");

get=checkConfig();
args=parser.parse_args();
print("\n\n")
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
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS");
        i=regions.index(args.region);
        connects=boto3.resource('ec2',args.region);
        connect=boto3.client('ec2',args.region);
        filterByTag(2);
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS");
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
            print('\033[34m'+"\n\t\t\tTAGGED INSTANCES")
            print('\033[32m'+"\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
            print('\033[0;37;40m')
            for ni in range(len(b)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[b[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n",regionsName[i],"\t\t",zt[ni],"\t\t",inst.instance_type,"\t\t",inst.id,"\t",inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",tag['Key'],"\t\t",tag['Value'])
            print('\033[34m'+"\n\t\t\tUNTAGGED INSTANCES")
            print('\033[32m'+"\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
            print('\033[0;37;40m')
            for ni in range(len(c)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[c[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n",regionsName[i],"\t\t",zu[ni],"\t\t",inst.instance_type,"\t\t",inst.id,"\t",inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",tag['Key'],"\t\t",tag['Value'])
            
                    
        else:
            print("\nREGION\t\t\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
            filterByTag(0);
            
    elif args.filter:
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(3);
        print('\033[34m'+"\n\t\t\tTAGGED INSTANCES")
        print('\033[32m'+"\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
        print('\033[0;37;40m')
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            for ni in range(len(b)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[b[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n",regionsName[i],"\t\t",zt[ni],"\t\t",inst.instance_type,"\t\t",inst.id,"\t",inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",tag['Key'],"\t\t",tag['Value'])
        print('\033[34m'+"\n\t\t\tUNTAGGED INSTANCES")
        print('\033[32m'+"\nREGION\t\t\t\tZONE\t\t\tINSTANCE TYPE\t\tINSTANCE ID\t\t\tPUBLIC IP ADDRESS\tKEY\t\tVALUE");
        print('\033[0;37;40m')
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            for ni in range(len(c)):
                getStaIns=connects.instances.filter(Filters=[
                {
                    'Name':'instance-id',
                    'Values':[c[ni]]
                    }
                ]);
                for inst in getStaIns:
                    print("\n\n",regionsName[i],"\t\t",zu[ni],"\t\t",inst.instance_type,"\t\t",inst.id,"\t\t",inst.public_ip_address)
                    if inst.tags:
                        for tag in inst.tags:
                            print("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",tag['Key'],"\t\t",tag['Value'])
        
                
    else:
        print("\nREGION\t\tZONE\t\tINSTANCE TYPE\t\tINSTANCE ID\t\tPUBLIC IP ADDRESS\t\tKEY NAME\t\tKEY VALUE\n");
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            filterByTag(0);
        






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
        print("ERROR:Add Slack API token using addtoken --token yourtokrn")


if args.options=="att-volume":#
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
if args.options=="un-att-volume":
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
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID")
        print("\n")
        Volume(2);     
    else:
        print("\n\nREGION\t\tAVAILABILITY-ZONE\t\tVOLUME ID\t\tVOLUME-STATE\t\tVOLUME-TYPE\t\tATTACHED-INSTANCEID")
        print("\n")
        for i in range(0,10):
            connects=boto3.resource('ec2',regions[i]);
            connect=boto3.client('ec2',regions[i]);
            Volume(2);
    
    

if args.options=="addtoken":
    addToken();

if args.options=="updatetoken":
    changeToken();



restore();
