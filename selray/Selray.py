from selray.utils import aws, utils, spray,write_output_files,Arguments
from selray.utils.SprayConfig import SprayConfig
from selray.utils.Azure import get_azure_context


# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

__version__ = "0.8"


# --------------------------------- #
# FUNCTIONS                         #
# --------------------------------- #

def main():
    results = []
    utils.initialize_playwright()
    args = Arguments.parse_args()  # The contents of args is documented in Arguments.py

    # Prepare spray configuration
    args = Arguments.prepare_args(args)
    spray_config = SprayConfig.from_args(args)

    if args.azure:
        args.azure_credentials, args.azure_subscription_id = get_azure_context()

    # Certain modes don't require running the whole script. Check to see if one of those should be executed.
    utils.alternate_modes(args)

    utils.print_beginning(args, version=__version__)

    try:
        # Perform credential stuffing, if that's what's in store:
        if (not args.passwords or args.passwords == ['']) and ":" in args.usernames[0]:
            results = utils.credential_stuffing(spray_config, args)
        else:
            results = spray.main(args, spray_config)

    finally:
        utils.destroy_proxies(args)
        utils.print_ending(results)
        write_output_files.main(args, results)


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
