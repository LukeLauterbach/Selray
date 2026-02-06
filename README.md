<p align="center">
  <img src="assets/screenshots/selray_logo.png" alt="Selray Logo" width="300">
</p>

<h1 align="center">Selray</h1>

<p align="center">
  <b>A flexible Selenium-based password spraying tool designed to evade common WAF detections.</b><br>
  <i>Selray = Selenium Spray</i>
</p>

## ✨ Features
- Bypasses WAFs by simulating real browser interactions
- Supports Azure proxy rotation to evade IP-based detections
- Handles complex login flows that require full form interaction
- Built-in delay system to avoid password lockout policies

## 📜 Description
Selray is a password spraying utility that leverages Selenium to avoid traditional web application firewall (WAF) detections, offering flexibility for targeting a variety of authentication portals.

![Example Screenshot](assets/screenshots/example.png)

Note: Selray no longer supports manual proxies or AWS proxies. If either were to be requested again, I'd be happy to re-add them. 

## 🚀 Usage

### Examples
```bash
selray -u test@example.com -p Password1 -dl 1 -uf 'name="username"' -pf 'name="password"' --url https://example.com -s Success
```
This is the most basic usage. A single username and password will be attempted against the login portal, with all requests coming from the origin's IP address.

```bash
selray -u usernames.txt -p passwords.txt -dl 60 -uf 'name="username"' -pf 'name="password"' --url https://example.com -s Success --azure -t 10 -n 10
```
Spray multiple users contained in a file. Attempt multiple passwords from a file, with 60 minutes between each individual password, to avoid an account lockout. Use 10 Azure proxies to bypass IP-based restrictions, and ensure that no more than 10 login attempts ever come from the same IP address.

### Modes
Selray includes pre-made modes that simplify the process of spraying specific targets. Modes are available in the modes folder and are created using TOML files. Currently, modes are available for:
* ADFS
* Azure
* Azure-Duo (For spraying the Azure portal with Duo utilized for SSO)
* Google
* Okta
* OWA - Outlook Web Access (still requires `--url`)
* Sophos

A mode can be specified with `-m {NAME}`

### Requirements
If no mode is specified, each run of the script requires five things:
- **`--url {URL}`** - URL of the website to spray.
- **`-u {USERNAME/S}`** – A username or file containing usernames. Optionally, a `username:password` list separated by a colon (e.g., `USER:PASS`).
- **`-p {PASSWORD/S}`** – A password or file containing passwords.
- **`-uf {USERNAME FIELD IDENTIFIER}`** – An HTML attribute unique to the username field you are trying to spray. In the example below, name="UserName" would be a valid value.
  ```html
  <input id="userNameInput" name="UserName" type="email" placeholder="someone@example.com" autocomplete="off">
  ```
- **`-pf {PASSWORD FIELD IDENTIFIER}`** – An HTML attribute unique to the password field. In the example below, name="Password" would be a valid value.
  ```html
  <input id="passwordInput" name="Password" type="password" placeholder="Password" autocomplete="off">
  ```

You must also specify either:
- **`-f`** – Text present in the page after a failed login, or
- **`-s`** – Text present in the page after a successful login.

### Options
- **`-m {MODE}`** – Use a pre-built mode to skip `-uf`, `-pf`, `-f`, `-s`, and `-i`.
- **`-t {INTEGER}`** – Number of concurrent threads (default: 5).
- **`-dl {INTEGER}`** – Delay (in minutes) between password rounds (default: 30).
- **`-i {TEXT[,TEXT]}`** – Comma-separated strings indicating invalid username.
- **`-l {TEXT[,TEXT]}`** – Comma-separated strings indicating lockout.
- **`-pl {TEXT[,TEXT]}`** – Comma-separated strings indicating passwordless/alternate flow.
- **`-nh`** – Disable headless mode (useful for troubleshooting; pop-up windows are intrusive).
- **`-cb {ATTR}`** – Checkbox attribute selector to click if required (same format as `-uf`/`-pf`).
- **`-d {DOMAIN}`** – Prefix usernames with `DOMAIN/USERNAME`.
- **`-db {DOMAIN}`** – Prefix usernames with `DOMAIN\USERNAME`.
- **`-da {DOMAIN}`** – Append domain to usernames (`USERNAME@DOMAIN`).
- **`-fp {PREFIX}`** – Prefix for output file names.
- **`-lm`** – List available built-in modes.
- **`--update [BRANCH]`** – Update tool (pipx only); optionally specify a branch.

## 🌐 Proxies
Selray can automatically spin up Azure proxies, rotating the proxy IP addresses and destroying the proxies upon script completion.
* **`--azure`** – Enable Azure proxy functionality

### Proxy Options
- **`-n {INTEGER}`** – Maximum spray attempts per IP (default: 5).
- **`-t {INTEGER}`** – Number of concurrent threads/Azure instances (default: 5).
- **`--proxy-list`** – List Azure instances created.
- **`--proxy-clean`** – Destroy Azure instances created by you (will also be done automatically at the end of spraying). This will not kill proxies made by other Azure accounts, even in the same Resource Group.
- **`--proxy-clean {VM NAME}`** – Destroy a specific VM (which can be a VM created by another Azure group)
- **`-arg {RESOURCE_GROUP}`** – Azure resource group to create proxies in (or set in en environment variable`AZURE_RG`).

## 📦 Installation
Install via `pipx`:
```bash
pipx install "git+https://github.com/LukeLauterbach/SeleniumSpray"
```

Or manually:
```bash
git clone https://github.com/LukeLauterbach/Selray
pip install -r requirements.txt
python selray/Selray.py
```
The first time you run Selray with Azure proxies, the script will prompt you to log into your Azure account. 


## ⚠️ Disclaimer
This tool is intended for authorized testing and educational purposes only.  
Unauthorized use against systems without permission is illegal and unethical.  
The author and all contributors assume no responsibility for misuse.
