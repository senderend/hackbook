# sender's custom scripts

These are designed to work with Kali Linux with a default shell of `zsh` but should also work with bash.To install simply place the files in a location that is in your `$PATH`, I used `/usr/local/bin` which is hard coded into variables at the top of the files that need it. You can change it per the config instructions below.

## Installation

For easy startup:

1. put all the contents of this folder ([scripts](/scripts/)) into `/usr/local/bin`
2. put all the contents of the [privEsc](/privEsc) into `/usr/local/share/privEsc`

All the scripts should then work out of the box.

## Usage

The two main commands you will call here are `wpe` and `lpe`. They will navigate to your privesc folder and spin up a web server for you, stage a script (for windows), and then spit out some prewritten commands for copy/pasting. They each take an argument for the web server port but default to port 80:

```bash
lpe
lpe 8080
```

`wpe` will also take an optional second positional argument for the staging script shell port:
```bash
wpe
wpe 8080
wpe 80 443
```

The rest of the scripts are helpers that are called from within the two above. The `DLstrings*` scripts are not very useful by themselves. The `stage` script however can be useful on its own. You may also notice a commented out command at the bottom to auto create a venom binary which you might find useful.

## Advanced Configuration

The two things these scripts need to know:
- the location that the helper subscripts are in (probably the same directory as the scripts themselves, but you can change it)
- the location of the privEsc folders that they will open and serve.

If you already have a privEsc folder for Linux or Windows, you can point the `lpe`, `wpe`, and `stage` scripts to them. The folder paths are hard coded in variables at the top of the files as such:

`lpe` (Linux Privilege Escalation):
```bash
## Location options:
location="/usr/local/share/privEsc/linux"
binLocation="/usr/local/bin"
```

`wpe` (Windows Privilege Escalation)
```bash
## Location options
location="/usr/local/share/privEsc/windows"
binLocation="/usr/local/bin"
```

`stage` (windows staged shell writer script):
```bash
# Set options
default_port="443"
stage_script_path="/usr/local/share/privEsc/windows/scripts"
```
> you can also set the default shell port if none is specified as an argument to the stage script