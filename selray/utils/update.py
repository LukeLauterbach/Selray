import subprocess
import shutil

def self_update(branch, github_url="https://github.com/LukeLauterbach/Selray"):
    if shutil.which("pipx") is None:
        print("Error: pipx is not installed or not in PATH.")
        return

    if isinstance(branch, str):
        github_url += f"@{branch}"

    print(f"Updating from {github_url}...")
    subprocess.run(["pipx", "install", "--force", f"git+{github_url}"], check=True)


if __name__ == "__main__":
    self_update(True)
