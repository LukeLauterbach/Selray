from selray.utils import aws, utils, spray,write_output_files,Arguments
from selray.utils.SprayConfig import SprayConfig
from selray.utils.Azure import get_azure_context
from selray.utils.credential_stuffing import perform_stuffing


# --------------------------------- #
# GLOBAL VARIABLES                  #
# --------------------------------- #

__version__ = "1.1"


# --------------------------------- #
# FUNCTIONS                         #
# --------------------------------- #

def main():
    results = []
    raw_args = Arguments.parse_args()  # The contents of args is documented in Arguments.py
    utils.debug_print(getattr(raw_args, "debug", False), "Starting Selray main workflow")
    utils.debug_print(getattr(raw_args, "debug", False), "Initializing Playwright runtime")
    utils.initialize_playwright()
    utils.debug_print(getattr(raw_args, "debug", False), "Preparing arguments and loading optional mode config")
    args = Arguments.prepare_args(raw_args)

    utils.print_beginning(args, version=__version__)

    if args.azure:
        utils.debug_print(args.debug, "Azure mode enabled; resolving resource group and Azure context")
        args.azure_resource_group = utils.check_azure_rg(args.azure_resource_group) # Make sure a Resource Group is detected
        args.azure_credentials, args.azure_subscription_id = get_azure_context()
        utils.debug_print(args.debug, f"Azure context ready with subscription_id='{args.azure_subscription_id}' and resource_group='{args.azure_resource_group}'")

    # Certain modes don't require running the whole script. Check to see if one of those should be executed.
    utils.debug_print(args.debug, "Checking alternate modes")
    utils.alternate_modes(args)

    spray_config = SprayConfig.from_args(args)
    utils.debug_print(args.debug, f"Spray config built; threads={spray_config.threads}, azure={spray_config.azure}, headless={spray_config.headless}")

    try:
        # Perform credential stuffing, if that's what's in store:
        if (not args.passwords or args.passwords == ['']) and ":" in args.usernames[0]:
            utils.debug_print(args.debug, "Entering credential stuffing path")
            results = perform_stuffing(spray_config, args)
        else:
            utils.debug_print(args.debug, "Entering password spray path")
            results = spray.main(args, spray_config)

    finally:
        utils.debug_print(getattr(args, "debug", False), "Running cleanup/finalization")
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
