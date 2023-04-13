import subprocess

def sha3_256(word):
    running = subprocess.run(["./sha3-256/sha3-test", "-w", word], capture_output=True)
    return running.stderr.decode()[:-1]