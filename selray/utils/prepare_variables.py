from . import utils

def main(args):
    # See if a pre-set mode should be loaded as the config
    if args.mode:
        utils.load_mode_config(args)

    args.fail, args.success = utils.prepare_success_fail(fail=args.fail, success=args.success)
    args.usernames = utils.process_file(args.usernames)
    args.passwords = utils.process_file(args.passwords) if args.passwords else [""]
    args.usernames = utils.prepare_usernames(args.usernames, args.domain, args.domain_after)
    args.url = utils.prepare_url(args.url)
    args.invalid_username = utils.prepare_invalid_username(invalid_username=args.invalid_username)
    args.lockout = utils.prepare_lockout(lockout_messages=args.lockout)

    """
    The following variables can be set by a modes file, but any value provided by the user should overwrite the value
    provided by the modes file.
    """
    if not args.threads:
        args.threads = 5
    if not args.num_sprays_per_ip:
        args.num_sprays_per_ip = 5

    return args