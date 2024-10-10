import subprocess

def restart_iptables():
    subprocess.run(
        ['sudo','netfilter-persistent','save'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
        )
    subprocess.run(
        ['sudo','systemctl','restart','netfilter-persistent'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
        )