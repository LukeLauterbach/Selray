class SprayConfig:
    def __init__(self, url, username_field_key, username_field_value,
                 password_field_key, password_field_value, checkbox_key, checkbox_value,
                 fail, success, invalid_username, num_sprays_per_ip, aws_access_key, aws_secret_key,
                 aws_session_token, aws_region):
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