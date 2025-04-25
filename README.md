# SeleniumSpray
## Description
Password spraying utility, utilizing Selenium to avoid common WAF detections and allowing for flexibility with target systems.
## Usage
### Examples
> -u test@example.com -p Password1 -dl 1 -uf 'name="username"' -pf 'name="password"' --url https://example.com -s Success

This is the most basic usage. A single username and password will be attempted against the login portal, with all requests coming from the origin's IP address. 

> -u usernames.txt -p passwords.txt -dl 60 -uf 'name="username"' -pf 'name="password"' --url https://example.com -s Success --aws -t 10 -n 10

Spray multiple users contained in a file. Attempt multiple passwords from a file, with 60 minutes between each individual password, to avoid an account lockout. Use 10 AWS provies to bypass IP-based restrictions, and ensure that no more than 10 login attempts ever come from the same IP address. 

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

## Proxies
Selray can optionally spin up proxies in AWS EC2. The proxies will be automatically deployed, stopped while delaying between passwords, and then destroyed when the spray completes.

To use the AWS proxy functionality, use `--aws`
  
### Proxy Options
* `-n` - Number of spray attempts per unique IP address. Default is 5. Every IP rotation will add a delay of approximately 1 minute on the thread. 
* `-t` - An EC2 instance will be created for each thread. The more threads, the faster the script, but the more EC2 instances that will be created. Default is 5. Up to 29 can be created with the AWS Free Tier. 
* `--proxy-list` - Lists all AWS EC2 instances created by Selray
* `--proxy-clean` - Destroys all AWS EC2 instances created by Selray (will not delete other EC2 instances).

### AWS Credential Configuration
AWS credentials can be configured in one of two ways:
* Environment Variables (Recommended)
  * `AWS_ACCESS_KEY_ID`
  * `AWS_SECRET_ACCESS_KEY`
  * `AWS_DEFAULT_REGION`
* Arguments
  * `--aws-access-key {ACCESS KEY}` 
  * `--aws-secret-key {SECRET ACCESS KEY}`
  * `--aws-region {AWS REGION}` - The default is US-EAST-2

### AWS Credential Setup
1. Log into the [IAM Console](https://us-east-1.console.aws.amazon.com/iam). 
2. Navigate to the `Users` tab, and then select `Create User`
   1. User name doesn't matter, and the account does not need access to the AWS Management Console
   2. `Attach Policies Directory`, and then select `AmazonEC2FullAccess`
   3. Finish creating the user
3. Select the user, and then select `Create access key`
   1. Select `Other` as the use case
   2. Copy the access key and secret access key from the final page

Your region can be selected from [AWS' list of regions](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html). 

The actual access the script needs could (and should) probably be limited to more specific privileges. 

## Installation
`pipx install "git+https://github.com/LukeLauterbach/SeleniumSpray"`

You can also install the requirements with `pipx install -r requirements.txt`, and then run `python selray/Selray.py`.