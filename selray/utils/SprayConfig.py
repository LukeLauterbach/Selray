from os import environ

class SprayConfig:
    def __init__(self, url, username_field_key, username_field_value,
                 password_field_key, password_field_value, checkbox_key, checkbox_value,
                 fail, success, invalid_username, num_sprays_per_ip, lockout, threads, pre_login_code, pre_password_code, post_login_code,
                 passwordless, headless, azure, azure_subscription_id, azure_resource_group, azure_location):
        self.username = None
        self.password = None
        self.url = url
        self.username_field_key = username_field_key
        self.username_field_value = username_field_value
        self.password_field_key = password_field_key
        self.password_field_value = password_field_value
        self.checkbox_key = checkbox_key
        self.checkbox_value = checkbox_value
        self.fail = fail
        self.success = success
        self.invalid_username = invalid_username
        self.num_sprays_per_ip = num_sprays_per_ip
        self.lockout = lockout
        self.threads = threads
        self.pre_login_code = pre_login_code
        self.pre_password_code = pre_password_code
        self.post_login_code = post_login_code
        self.passwordless = passwordless
        self.headless = headless
        self.azure = azure
        self.azure_subscription_id = azure_subscription_id
        self.azure_resource_group = azure_resource_group
        self.azure_location = azure_location


    def prepare_username_fields(self, username_argument_value):
        if not username_argument_value:
            return False

        username_argument_value = username_argument_value.replace("'", "").replace('"', "")  # Remove quotation marks

        username_argument_value = username_argument_value.split("=")
        self.username_field_key = username_argument_value[0]
        self.username_field_value = username_argument_value[1]


    def prepare_password_fields(self, password_argument_value):
        if not password_argument_value:
            return False

        password_argument_value = password_argument_value.replace("'", "").replace('"', "")  # Remove quotation marks

        password_argument_value = password_argument_value.split("=")
        self.password_field_key = password_argument_value[0]
        self.password_field_value = password_argument_value[1]


    def prepare_azure_variables(self):
        if not self.azure_resource_group:
            self.azure_resource_group = (
                environ.get("AZURE_RG")
                or environ.get("AZURE_RESOURCE_GROUP")
                or ""
            )
        if not self.azure_location:
            self.azure_location = environ.get("AZURE_LOCATION", "eastus")
        if not self.azure_subscription_id:
            self.azure_subscription_id = environ.get("AZURE_SUBSCRIPTION_ID", "")

        # Normalize environment-provided values to avoid whitespace-only input.
        self.azure_resource_group = str(self.azure_resource_group or "").strip()
        self.azure_location = str(self.azure_location or "eastus").strip() or "eastus"
        self.azure_subscription_id = str(self.azure_subscription_id or "").strip()


    @classmethod
    def from_args(cls, args):
        instance = cls(
            url=args.url,
            username_field_key = None,
            username_field_value = None,
            password_field_key = None,
            password_field_value = None,
            checkbox_key = None,
            checkbox_value = None,
            fail=args.fail,
            success=args.success,
            invalid_username=args.invalid_username,
            num_sprays_per_ip=args.num_sprays_per_ip,
            lockout=args.lockout,
            threads=args.threads,
            pre_login_code=getattr(args, "pre_login_code", ""),
            pre_password_code=getattr(args, "pre_password_code", ""),
            post_login_code=getattr(args, "post_login_code", ""),
            passwordless=getattr(args, "passwordless", ""),
            # This next one is confusing. We're flipping from "no headless" to "headless".
            headless=not getattr(args, "no_headless", True),
            azure=getattr(args, "azure", False),
            azure_subscription_id=getattr(args, "azure_subscription_id", ""),
            azure_resource_group=getattr(args, "azure_resource_group", ""),
            azure_location=getattr(args, "azure_location", ""),
        )

        instance.prepare_username_fields(args.username_field)
        instance.prepare_password_fields(args.password_field)
        instance.prepare_azure_variables()

        return instance
