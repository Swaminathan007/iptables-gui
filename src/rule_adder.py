import subprocess as sp
from .restart import *
def add_rule(rule,table_name):
    actual_rule = ['sudo','iptables','-t',table_name]
    #FOR CHAIN WITH OR WITHOUT LINE NUMBERS
    if(rule[6]):
        actual_rule.extend(["-I",rule[0],rule[6]])
    else:
        actual_rule.extend(["-A",rule[0]])

    if(rule[1] != "any"):
        actual_rule.extend(["-p",rule[1]])
    
    if(rule[2] != "0.0.0.0/0"):
        actual_rule.extend(["-s",rule[2]])
    if(rule[3] != "0.0.0.0/0"):
        actual_rule.extend(["-d",rule[3]])
    if(rule[4] != "any"):
        actual_rule.extend(["--sport",rule[4]])
    if(rule[5] != "any"):
        actual_rule.extend(["--dport",rule[5]])
    
    actual_rule.extend(['-j',rule[7]])
    if(rule[8]):
        actual_rule.extend(["--to-destination",rule[8]])
    sp.run(
        actual_rule,
        stdout=sp.PIPE,
        stderr=sp.PIPE,
        text=True,
        check=True
    )
    restart_iptables()