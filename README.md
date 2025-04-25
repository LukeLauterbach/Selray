# SeleniumSpray
## Description
Password spraying utility, utilizing Selenium to avoid common WAF detections and allowing for flexibility with target systems.
## Usage
### Requirements
Each run of the script always requires four things:
* `-u {USERNAME/S}` - Either a username or a file with a list of passwords. Alternatively, a list of usernames and passwords can be provided, seperated by a colon (e.g. USER:PASS)
* `-p {PASSWORD/S}` - Either a password or a file with a list of passwords.
* `-uf {USERNAME FIELD IDENTIFIER}` - An HTML attribute that is unique to the username field where you want usernames to be entered. For the example below, `name=UserName` would work.
    
    ```<input id="userNameInput" name="UserName" type="email" value="" tabindex="1" class="text fullWidth" spellcheck="false" placeholder="someone@example.com" autocomplete="off">```
* `-pf {PASSWORD FIELD IDENTIFIER}` - An HTML attribute that is unique to the password field where you want passwords to be entered. For the example below, `name=Password` would work.
    
    ```<input id="passwordInput" name="Password" type="password" tabindex="2" class="text fullWidth" placeholder="Password" autocomplete="off">```
Additionally, the script needs to be told what a valid login looks like. That can be accomplished with one of the following two things:
* `-f` - Text which only appears on the page if a failed login occurs.
* `-s` - Text which only appears on the page if a successful login occurs. 
### Options
The following arguments can be provided to change the execution of the script. 
* `-t` - Change the number of concurrent login attempts (the default is 5). Keep in mind, this script is emulating a browser for each thread, so it will inherently be slower than most POST-based spraying tools.
* `-dl` - Length of time between passwords. The delay is between the first spray attempt with a password and the first attempt with the next password. Default is 30.
* `-i` - String(s) to look for to determine if the username was invalid. Multiple strings can be provided comma seperated with no spaces.
* `-cb` - If a checkbox is required, provide a unique attribute of the checkbox, allowing the script to automatically check it. For example, if `<input type='checkbox'>`, enter 'type='checkbox''
* `-d` - Prefix all usernames with a domain (e.g. DOMAIN\USERNAME)
* `-da` - Postfix all usernames with a domain (e.g. USERNAME@DOMAIN)

## Installation
`pipx install "git+https://github.com/LukeLauterbach/SeleniumSpray"`

You can also 