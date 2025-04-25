from . import aws
import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(description="Performs a password spraying attack utilizing Selenium.")
    required = parser.add_argument_group("Required")
    condition = parser.add_argument_group("Condition for Successful Login (One Required)")
    optional = parser.add_argument_group("Optional")
    aws_group = parser.add_argument_group("AWS Proxy Options")

    required.add_argument('--url',
                          help="(REQUIRED) URL of the website to spray.")
    optional.add_argument("-d", "--domain",
                          help="(OPTIONAL) Prefix all usernames with a domain (e.g. DOMAIN\\USERNAME)")
    optional.add_argument("-da", "--domain-after", action="store_true",
                          help="(OPTIONAL) Append domain to the end of the username (e.g. username@domain)")
    required.add_argument("-p", "--passwords",
                          help="(REQUIRED) Password or file with list of usernames to spray.")
    condition.add_argument('-f', '--fail',
                           help="(OPTIONAL) Text which will be on the page if authentication fails. -s can be used as "
                                "an alternative.")
    condition.add_argument('-s', '--success',
                           help="(OPTIONAL) Text which will be on the page if authentication is successful. -f can be "
                                "used as an alternative")
    required.add_argument("-u", "--usernames",
                          help="(REQUIRED) Username or file with list of usernames to spray. Alternatively, can be a"
                               "list of colon-seperated credentials to spray (e.g. USER:PASS)")
    optional.add_argument("-i", "--invalid-username", type=str,
                          help="(OPTIONAL) String(s) to look for to determine if the username was invalid. Multiple "
                               "strings can be provided comma seperated with no spaces.")
    required.add_argument('-uf', '--username-field', type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")
    required.add_argument('-pf', '--password-field', type=str,
                          help="(REQUIRED) Input field attribute, used to identify which field should be used to put"
                               "a username into. Can be found by inspecting the username field in your browser. For"
                               "example, if '<input type='email'>', enter 'type='email''")
    optional.add_argument('-cb', '--checkbox', type=str,
                          help="(OPTIONAL) If a checkbox is required, provide a unique attribute of the checkbox, "
                               "allowing the script to automatically check it. For example, if "
                               "'<input type='checkbox'>', enter 'type='checkbox''")

    optional.add_argument('-t', '--threads', type=int, default=5,
                          help="(OPTIONAL) Number of threads for passwords spraying. Lower is stealthier. "
                               "Default is 5.")
    optional.add_argument('-dl', '--delay', type=int, default=30,
                          help="(OPTIONAL) Length of time between passwords. The delay is between the first spray "
                               "attempt with a password and the first attempt with the next password. Default is 30.")
    optional.add_argument('-n','--num_sprays_per_ip', type=int, default=5, help="(OPTIONAL) Number of sprays to perform per IP address. Default is 5.")
    optional.add_argument('--aws', action='store_true', help="(OPTIONAL) Use AWS proxies. Default is False.")
    optional.add_argument('--proxy-clean', action='store_true', help="(OPTIONAL) Clean up all created proxies, instead of spraying.")
    optional.add_argument('--proxy-list', action='store_true', help="(OPTIONAL) List all created proxies.")

    aws_group.add_argument("--aws-access-key", help="AWS Access Key ID")
    aws_group.add_argument("--aws-secret-key", help="AWS Secret Access Key")
    aws_group.add_argument("--aws-session-token", help="AWS Session Token (optional)")
    aws_group.add_argument("--aws-region", default="us-east-2", help="AWS Region")

    return parser.parse_args()


def prepare_proxies(ec2, args):
    if args.aws:
        proxies = aws.proxy_setup(ec2, args.threads)
    else:
        proxies = [{"type": None, "ip": None, "id": None} for _ in range(args.threads)]

    return proxies  # Proxies will always be a list of dicts.


def destroy_proxies(args, ec2):
    if ec2:
        aws.terminate_instances_in_security_group(ec2, "Selray")
    exit()

def list_proxies(args, ec2):
    if ec2:
        aws.list_instances(ec2, "Selray")
    exit()