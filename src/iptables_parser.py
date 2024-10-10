import subprocess
import re

def parse_iptables_output(output):
    """
    Parses iptables output into a dictionary.
    
    Args:
        output (str): The raw output from the iptables command.
        
    Returns:
        dict: A dictionary where keys are chain names and values are lists of rules.
    """
    lines = output.split("\n")
    cur_chain = None
    chain = {}
    for line in lines:
        if(line.startswith("Chain")):
            cur_chain = line.split(" ")[1]    
            chain[cur_chain] = []        
        elif(len(line) > 0 and line[0].isdigit()):
            rule = line.split(" ")
            chain_rule = {}
            chain_rule["line"] = rule[0]
            chain_rule["action"] = rule[4]
            chain[cur_chain].append(chain_rule)

    return chain
def get_chains(table):
        result = subprocess.run(
        ['sudo','iptables','-t',table,'-L','-n','--line-numbers'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True)

        result = result.stdout
        lines = result.split("\n")
        chains = []
        for line in lines:
            if(line.startswith("Chain")):
                cur_chain = line.split(" ")[1]    
                chains.append(cur_chain)
        return chains 