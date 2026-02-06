from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_ed25519_openssh_keypair() -> tuple[str, str]:
    """
    Returns (private_key_pem, public_key_openssh)
    - private_key_pem: PEM text you should save securely (and delete when done)
    - public_key_openssh: the 'ssh-ed25519 AAAA...' line you pass to Azure
    """
    private_key = ed25519.Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,  # OpenSSH private key format
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_openssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")

    return private_pem, public_openssh
