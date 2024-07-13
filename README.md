# Write-up for underthewire.tech/century
Powershell walkthroughs for Century Wargames on [underthewire](https://underthewire.tech/wargames).  
(Note: all passwords are lowercase)

## Century1
The goal of this level is to log into the game using credentials obtained via Slack.
The password, when prompted, is **century1**.
```powershell
PS C:\users\TheLinuxJedi\desktop> ssh century1@century.underthewire.tech -p 22
```

## Century2
The password for Century2 is the build version of the instance of PowerShell installed on this system.
```powershell
PS C:\users\century1\desktop> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.1.14393.6343
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.14393.6343
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
```
The password for Century2 is: **10.0.14393.6343**

## Century3
The password for Century3 is the name of the built-in cmdlet that performs the wget like function within PowerShell PLUS the name of the file on the desktop.  
First we will search the help files for a cmdlet that contains the phrase "wget".
```powershell
PS C:\users\century2\desktop> get-help *wget*


Name          : wget
Category      : Alias
Synopsis      : Invoke-WebRequest
Component     :
Role          :
Functionality :
```
Next we will find the name of the file on the desktop.
```powershell
PS C:\users\century2\desktop> get-childitem


    Directory: C:\users\century2\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM            693 443
```
Putting these together we get the password for Century3: **invoke-webrequest443**  

## Century4
The password for Century4 is the number of files on the desktop.
We can find this by printing a directory listing, and piping the output to measure-object.
```powershell
PS C:\users\century3\desktop> Get-ChildItem | Measure-Object | Select-Object -Property Count

Count
-----
  123
```
The password for Century4 is: **123**


## Century5
The password for Century5 is the name of the file within a directory on the desktop that has spaces in its name.
We can do this one easily by adding a recursive parameter to the Get-ChildItem command.
```powershell
PS C:\users\century4\desktop> Get-ChildItem -recurse


    Directory: C:\users\century4\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/14/2024   2:35 PM                Can You Open Me


    Directory: C:\users\century4\desktop\Can You Open Me


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/14/2024   2:35 PM             24 34182
```
The password for Century5 is: **34182**


## Century6
The password for Century6 is the short name of the domain in which this system resides in PLUS the name of the file on the desktop.
We can get the short name of the domain using the get-addomain command, and selecting the "Name" property.
```powershell
PS C:\users\century5\desktop> get-addomain | Select-Object -Property Name

Name
----
underthewire
```
To get the name of the file on the desktop we perform another directory listing. Underthewire loves using the name of the file on the desktop. Too easy.
```powershell
PS C:\users\century5\desktop> Get-ChildItem -Name
3347
```
Putting these together we geth the password for Century6: **underthewire3347**

## Century7
The password for Century7 is the number of folders on the desktop.
We can get this number by performing a directory listing, and measuring the amount of objects listed.
```powershell
PS C:\users\century6\desktop> Get-ChildItem -Directory | Measure-Object | Select-Object Count

Count
-----
  197
```
We could also get this number by performing a directory listing, and measuring the amount of lines in the output.
```powershell
PS C:\users\century6\desktop> Get-ChildItem -Directory | Measure-Object -Line

Lines Words Characters Property
----- ----- ---------- --------
  197
```
The password for Century7 is: **197**

## Century8
The password for Century8 is in a readme file somewhere within the contacts, desktop, documents, downloads, favorites, music, or videos folder in the user’s profile.
This time we will move from the desktop to the C:\users\Century7 directory. From there we can run a recursive search for any file that begins with "readme".
```powershell
PS C:\users\century7> Get-ChildItem -Recurse -File -Filter readme* | Get-Content
7points
```
The password for Century8 is: **7points**

## Century9
The password for Century9 is the number of unique entries within the file on the desktop.
For this challenge we will string together a few commands to get the desired output.  
First we need to know the name of the file on the desktop.
```powershell
PS C:\users\century8\desktop> Get-ChildItem -Name
unique.txt
```
Now we can get the content of the file, sort it, identify unique lines, and finally measure the amount of unique lines we have.   
All together it will look like this:
```powershell
PS C:\users\century8\desktop> Get-Content .\unique.txt | Sort-Object | Get-Unique | Measure-Object | Select-Object Count

Count
-----
  696
```
The password for Century9 is: **696**

## Century10
The password for Century10 is the 161st word within the file on the desktop.
For this challenge we can split every word into it's own line, then isolate the 161st line.  
(Note: since we start counting at 0, we will index for the 160th line, this will give us the 161st word.)
```powershell
PS C:\users\century9\desktop> (Get-Content .\Word_File.txt) -split ' ' | Select-Object -Index 160
pierid
```
The password for Century10 is: **pierid**

## Century11
The password for Century11 is the 10th and 8th word of the Windows Update service description combined PLUS the name of the file on the desktop.
I did not know the name of the Windows Update service, so I began by querying the services for something with a display name that matches what I was searching for.
```powershell
PS C:\users\century9\desktop> Get-Service -DisplayName "windows update"

Status   Name               DisplayName
------   ----               -----------
Stopped  wuauserv           Windows Update
```
Now that we have the name of the service we can use Get-CimInstance to retrieve the description of the service.
```powershell
PS C:\users\century9\desktop> Get-CimInstance -ClassName Win32_Service | Where-Object -Property Name -eq "wuauserv" | Select-Object Description

Description
-----------
Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer will
```
I could add more commands to filter out the 10th and 8th words in the description, but counting is easier.  
The 10th word is "windows", and the 8th word is "updates"
Then we find the name of the file on the desktop.
```powershell
PS C:\users\century10\desktop> Get-ChildItem -Name
110
```
The password for Century11 is: **windowsupdates110**

## Century 12
The password for Century12 is the name of the hidden file within the contacts, desktop, documents, downloads, favorites, music, or videos folder in the user’s profile.  
To begin we will move up a directory into C:\users\century11. From here we can recursively search for hidden files.  
(Note: more files were found using this query, but we can rule out .dat and .ini files. Leaving us with only the text file we want.)
```powershell
PS C:\users\century11> Get-ChildItem -Recurse -File -Hidden -ErrorAction SilentlyContinue

    Directory: C:\users\century11\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--rh--        8/30/2018   3:34 AM             30 secret_sauce
```
The password for Century12 is: **secret_sauce**

## Century 13
The password for Century13 is the description of the computer designated as a Domain Controller within this domain PLUS the name of the file on the desktop.

```powershell

```
The password for Century13 is: **123**

## Century 14
```powershell
```
The password for Century14 is: **123**

## Century 15
```powershell
```
The password for Century15 is: **123**
