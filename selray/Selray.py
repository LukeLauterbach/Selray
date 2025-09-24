from selray.utils import aws, utils, prepare_variables, spray
from selray.utils.SprayConfig import SprayConfig

# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

__version__ = "0.7"


# --------------------------------- #
# FUNCTIONS                         #
# --------------------------------- #

def main():
    results = []
    utils.initialize_playwright()
    args = utils.parse_arguments()

    # Prepare spray configuration
    args = prepare_variables.main(args)
    spray_config = SprayConfig.from_args(args)

    # Connect to AWS, if using proxies
    ec2 = aws.get_ec2_session(args.aws_region, args.aws_access_key, args.aws_secret_key, args.aws_session_token)

    # Certain modes don't require running the whole script. Check to see if one of those should be executed.
    utils.alternate_modes(args, ec2)

    utils.print_beginning(args, version=__version__)

    proxies = utils.prepare_proxies(ec2, args)

    try:
        # Perform credential stuffing, if that's what's in store:
        if (not args.passwords or args.passwords == ['']) and ":" in args.usernames[0]:
            results = utils.credential_stuffing(spray_config, args, proxies)
        else:
            results = spray.main(args, proxies, spray_config)

    finally:
        utils.destroy_proxies(args, ec2)
        utils.print_ending(results)


# --------------------------------- #
# MAIN                              #
# --------------------------------- #

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCtrl+C Detected")
        utils.print_ending([{'USERNAME': '', 'PASSWORD': '', 'RESULT': 'CANCELLED'}])
        exit()
