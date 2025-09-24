class SprayConfig:
    def __init__(self, url, username_field_key, username_field_value,
                 password_field_key, password_field_value, checkbox_key, checkbox_value,
                 fail, success, invalid_username, num_sprays_per_ip, aws_access_key, aws_secret_key,
                 aws_session_token, aws_region, lockout, threads, pre_login_code, pre_password_code, passwordless, headless):
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
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.aws_region = aws_region
        self.aws_session_token = aws_session_token
        self.lockout = lockout
        self.threads = threads
        self.pre_login_code = pre_login_code
        self.pre_password_code = pre_password_code
        self.passwordless = passwordless
        self.headless = headless


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
            aws_region=args.aws_region,
            aws_access_key=args.aws_access_key,
            aws_secret_key=args.aws_secret_key,
            aws_session_token=args.aws_session_token,
            lockout=args.lockout,
            threads=args.threads,
            pre_login_code=getattr(args, "pre_login_code", ""),
            pre_password_code=getattr(args, "pre_password_code", ""),
            passwordless=getattr(args, "passwordless", ""),
            # This next one is confusing. We're flipping from "no headless" to "headless".
            headless=not getattr(args, "no_headless", True)
        )

        instance.prepare_username_fields(args.username_field)
        instance.prepare_password_fields(args.password_field)

        return instance
