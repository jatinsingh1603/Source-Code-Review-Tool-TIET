import os

target = os.environ["TARGET"]
command = "ls " + target
os.system(command)
