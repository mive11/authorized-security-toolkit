# Windows setup (WSL 2)

The complete Authorized Security Toolkit workflow is not native to Windows: Passive Domain Inventory and ScopeGuard use POSIX facilities. Run the repository inside WSL 2. The tools remain local-first; this setup does not change their network behavior.

## Install WSL

In an elevated PowerShell window, install Ubuntu with:

```powershell
wsl --install -d Ubuntu
```

Restart Windows if prompted, then finish Ubuntu's first-run user setup. See Microsoft's [official WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install) for current requirements and troubleshooting.

## Clone and use the toolkit

In the Ubuntu terminal:

```bash
sudo apt update
sudo apt install -y git python3
mkdir -p ~/src
cd ~/src
git clone https://github.com/mive11/authorized-security-toolkit.git
cd authorized-security-toolkit
python3 scripts/test_all.py
```

The suite uses Python's standard library and Bash; it does not require third-party Python packages. The test runner uses offline fixtures and temporary directories. Review the individual tool documentation before using any tool, and assess only systems you own or have explicit authorization to test.

Keep Linux projects under the WSL Linux home directory (such as `/home/<user>/src`) for better performance. Windows can access those files at `\\wsl.localhost\Ubuntu\home\<user>\src`. See Microsoft's [WSL file-system guidance](https://learn.microsoft.com/en-us/windows/wsl/filesystems).

## Native Windows status

Native Windows support is not claimed. In particular, Bash and POSIX `fcntl` / `SIGALRM` behavior are not available through standard PowerShell. Use WSL 2 for the complete workflow; do not silently replace the scope or audit controls with Windows-specific behavior.
