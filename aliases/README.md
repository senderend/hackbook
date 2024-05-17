# Shell Aliases and Functions

### Writeup

Check out my [writeup](https://senderend.medium.com/my-oscp-efficiency-aliases-and-functions-bd82a91b147f) for a more in-depth walkthru of each of these commands

### Instructions

add these to the end of your .bashrc or .zshrc file, then start a new terminal (or source the .rc file)

```bash
#-------------aliases and functions by sender https://github.com/allendemoura--------------------
# shared history config
setopt inc_append_history
#setopt share_history

# custom history search by entered command
bindkey "^[OA" history-beginning-search-backward
bindkey "^[OB" history-beginning-search-forward

# shift+enter moves to end of command
bindkey '^[OM' end-of-line

# custom vars
myip=$(ip addr show tun0 | grep -oP 'inet \K[\d.]+')
smbAddress="\\\\\\${myip}\\share"

# efficiency aliases
alias lla='ls -lah'
alias oscp='cd ~/Documents/OSCP'
function mkcd() { mkdir -p "$1" && cd "$1"; }
alias f='function _myfind() { root="${2:-/}"; find "$root" -iname "*$1*" 2>/dev/null; }; _myfind'
alias ff='function _myfind2() { root="${2:-/}"; find "$root" -iname "$1" 2>/dev/null; }; _myfind2'
ketch() { nc -lvnp "${1:-443}"; }
rketch() { rlwrap nc -lvnp "${1:-443}"; }
wketch() { stty raw -echo; (stty size; cat) | nc -lvnp "${1:-443}"; }
alias pse='rlwrap impacket-psexec'
alias smbserver='echo -ne "\033]0;SMBserv\007"; echo "net use x: $smbAddress /user:sender password"; impacket-smbserver share . -username sender -password password -smb2support'
function hc() { hashcat $1 /usr/share/wordlists/rockyou.txt $@ -O}
```