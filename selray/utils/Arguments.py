from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union, Sequence
from argparse import ArgumentParser, Namespace
from json import dumps
from dataclasses import asdict
from . import utils


@dataclass
class SelrayArgs:
    # Required
    url: str
    usernames: str
    passwords: str
    username_field: str
    password_field: str

    # Condition for Successful Login (one required)
    fail: Optional[str] = None
    success: Optional[str] = None

    # Optional
    mode: Optional[str] = None
    threads: int = 5
    delay: int = 30

    domain: Optional[str] = None
    domain_backslash: Optional[str] = None
    domain_after: Optional[str] = None

    invalid_username: Optional[str] = None
    lockout: Optional[str] = None
    passwordless: Optional[str] = None

    no_headless: bool = False
    checkbox: Optional[str] = None
    file_prefix: str = ""
    list_modes: bool = False

    # False -> not used, True -> used without arg, "branch" -> used with arg
    update: Union[bool, str] = False

    # Global Proxy Options
    proxy_clean: bool = False
    proxy_list: bool = False
    num_sprays_per_ip: int = 5

    # Azure proxy
    azure: bool = False
    azure_credentials: Optional[object] = None
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    azure_region: Optional[str] = None


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(description="Performs a password spraying attack utilizing Selenium.")
    required = parser.add_argument_group("Required")
    condition = parser.add_argument_group("Condition for Successful Login (One Required)")
    optional = parser.add_argument_group("Optional")
    # aws_group = parser.add_argument_group("AWS Proxy Options")  # add later when implemented
    azure_group = parser.add_argument_group("Azure Proxy Options")
    proxy_group = parser.add_argument_group("Global Proxy Options")

    # Required args (actually required)
    required.add_argument("--url", required=False, help="(REQUIRED) URL of the website to spray.")
    required.add_argument(
        "-u", "--usernames", required=False,
        help="(REQUIRED) Username or file with list of usernames to spray. Alternatively, can be a "
             "list of colon-separated credentials to spray (e.g. USER:PASS)"
    )
    required.add_argument(
        "-p", "--passwords", required=False,
        help="(REQUIRED) Password or file with list of usernames to spray."
    )
    required.add_argument(
        "-uf", "--username-field", dest="username_field", type=str,
        help="(REQUIRED) Input field attribute used to identify the username input. Example: type='email'"
    )
    required.add_argument(
        "-pf", "--password-field", dest="password_field", type=str,
        help="(REQUIRED) Input field attribute used to identify the password input. Example: type='password'"
    )

    # One of these required (validated after parse)
    condition.add_argument(
        "-f", "--fail",
        help="(OPTIONAL) Text on the page if authentication fails. -s can be used as an alternative."
    )
    condition.add_argument(
        "-s", "--success",
        help="(OPTIONAL) Text on the page if authentication is successful. -f can be used as an alternative."
    )

    # Optional
    optional.add_argument(
        "-m", "--mode",
        help="Use a pre-built mode, eliminating the need for -uf,-pf,-f,-s, and -i."
    )
    optional.add_argument(
        "-t", "--threads", type=int, default=5,
        help="(OPTIONAL) Number of threads for password spraying. Default is 5."
    )
    optional.add_argument(
        "-dl", "--delay", type=int, default=30,
        help="(OPTIONAL) Delay between password rounds. Default is 30."
    )
    optional.add_argument("-d", "--domain", help="(OPTIONAL) Prefix usernames with DOMAIN/USERNAME")
    optional.add_argument("-db", "--domain-backslash", dest="domain_backslash",
                          help=r"(OPTIONAL) Prefix usernames with DOMAIN\USERNAME")
    optional.add_argument("-da", "--domain-after", dest="domain_after",
                          help="(OPTIONAL) Append domain (username@domain)")
    optional.add_argument(
        "-i", "--invalid-username", dest="invalid_username", type=str,
        help="(OPTIONAL) Comma-separated strings indicating invalid username (no spaces)."
    )
    optional.add_argument(
        "-l", "--lockout", type=str,
        help="(OPTIONAL) Comma-separated strings indicating lockout (no spaces)."
    )
    optional.add_argument(
        "-pl", "--passwordless", type=str,
        help="(OPTIONAL) Comma-separated strings indicating passwordless/alternate flow (no spaces)."
    )
    optional.add_argument("-nh", "--no-headless", action="store_true", default=False)
    optional.add_argument(
        "-cb", "--checkbox", type=str,
        help="(OPTIONAL) Unique attribute of required checkbox. Example: type='checkbox'"
    )
    optional.add_argument("-fp", "--file_prefix", type=str, default="",
                          help="(OPTIONAL) Prefix for output file names.")
    optional.add_argument("-lm", "--list_modes", action="store_true", default=False,
                          help="(OPTIONAL) List all built-in modes available.")

    optional.add_argument(
        "--update",
        nargs="?", const=True, default=False,
        help="(OPTIONAL) Update tool (pipx only). Optionally specify branch: --update BRANCH"
    )

    # Global proxies
    proxy_group.add_argument("--proxy-clean", action="store_true",
                             help="(OPTIONAL) Clean up created proxies instead of spraying.")
    proxy_group.add_argument("--proxy-list", action="store_true",
                             help="(OPTIONAL) List created proxies.")
    proxy_group.add_argument(
        "-n", "--num_sprays_per_ip", type=int, default=5,
        help="(OPTIONAL) Number of sprays per IP. Default is 5."
    )

    # Azure
    azure_group.add_argument("--azure", action="store_true",
                             help="(OPTIONAL) Use Azure proxies. Default is False.")
    azure_group.add_argument('-arg', '--azure-resource-group', type=str, default=None,
                             help="(OPTIONAL) The name of the Azure resource group to create the proxies in. This is required for Azure proxy usage. Alternative, put your resource group name in an environment variable named AZURE_RG.")

    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> SelrayArgs:
    parser = build_parser()
    ns: Namespace = parser.parse_args(argv)
    args = SelrayArgs(**vars(ns))
    return args


def print_args(args):
    d = asdict(args)
    if d.get("azure_credentials") is not None:
        d["azure_credentials"] = type(d["azure_credentials"]).__name__
    print(dumps(d, indent=2))


def prepare_args(args):
    # See if a pre-set mode should be loaded as the config
    if args.mode:
        utils.load_mode_config(args)

    args.fail, args.success = utils.prepare_success_fail(fail=args.fail, success=args.success)
    args.usernames = utils.process_file(args.usernames)
    args.passwords = utils.process_file(args.passwords) if args.passwords else [""]
    args.usernames = utils.prepare_usernames(args.usernames, args.domain, args.domain_after, args.domain_backslash)
    args.url = utils.prepare_url(args.url)
    args.invalid_username = utils.prepare_invalid_username(invalid_username=args.invalid_username)
    args.lockout = utils.prepare_lockout(lockout_messages=args.lockout)
    args.passwordless = utils.prepare_passwordless(passwordless_auth=args.passwordless)

    if args.file_prefix:
        args.file_prefix = args.file_prefix + "_"

    """
    The following variables can be set by a modes file, but any value provided by the user should overwrite the value
    provided by the modes file.
    """
    if not args.threads:
        args.threads = 5
    if not args.num_sprays_per_ip:
        args.num_sprays_per_ip = 5

    return args