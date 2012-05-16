#! /usr/bin/python

import argparse
import os
import pwd
import subprocess
import string
import random
import signal
import sys
import re
import shutil
import stat
import time
from ptrace.debugger.debugger import *
from ptrace.debugger.process_error import *

PTRACE_O_TRACEEXIT = 0x00000040
btrfs_create_root_snapshot = '/sbin/btrfs subvolume snapshot / /pcm'.split()
btrfs_create_home_snapshot = '/sbin/btrfs subvolume snapshot /home /home/pcm'.split()

btrfs_delete_root_snapshot = '/sbin/btrfs subvolume delete /pcm'.split()
btrfs_delete_home_snapshot = '/sbin/btrfs subvolume delete /home/pcm'.split()

def fatrace_fork(login_name, pid_pcm_program, filename):
    pid = os.fork()
    if not pid:
        # Make this file non readable to other members
        so = se = open(filename, 'w')
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
	print 'Starting fatrace tracing ...'
        os.execvp("/usr/local/sbin/fatrace", ("fatrace",))
    else:
        #print pid_pcm_program
        time.sleep(5)
        # We wait for the child process so 
        # has to get the correct status of the child 
        # program and not of su
        #print int(child_pid)
        print 'Starting ptrace tracing ...'
        d = PtraceDebugger()
        d.options |= PTRACE_O_TRACEEXIT
        process = d.addProcess(pid_pcm_program, False)
        #print process.is_stopped
        process.cont()
        #print process.is_stopped
        while True:
            try:
                event = process.waitEvent()
                #print event
                process.cont()
            except ProcessError:
                break

        maps = process.readMappings()
        print 'Clearing userland pages ....'
        map_count = 0
        for m in maps:
            if map_count == 5:
                break
            if m.pathname is None or m.pathname[0] != '/':
                if m.permissions[1] == 'w' and m.permissions[3] == 'p':
                    print 'Memory range ' + str(map_count + 1)
                    diff = (m.end - m.start) / 8
                    process.writeBytes(m.start, '0' * diff)
                    map_count += 1

        print 'Done clearing userland'
        os.kill(pid_pcm_program, signal.SIGTERM)
        os.kill(pid, signal.SIGTERM)
    return
# Clean up the temp file after extracing 
# useful information from it 

def child(*args):
    # Get Pid first  and then use os.system
    # or use os.execve
    #print args[0][0]
    arg_tuple = tuple(args[0])
    #print args
    os.execvp(arg_tuple[0], arg_tuple)
    
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

# Maybe you can detect if the directory is a subvolume or not
def snapshot_file_path(path):
    path_split = path.split('/')
    if path_split[1] == 'home':
        path_split[1] = 'home/pcm'
    else:
        path_split[1] = 'pcm' + '/' + path_split[1]

    return '/'.join(path_split)


parser = argparse.ArgumentParser(description="Private Computing Mode Wrapper")
parser.add_argument("-p", "--policy", dest="filename", type=str, help="policy file for pcm")
parser.add_argument('program_args', type=str, nargs='+', help='Name of the program to run in pcm mode and its arguments')
parser.add_argument('-l', "--login", dest="login_name", type=str, help="who are you ?")
args = parser.parse_args()

# Sets for getting the files changed by 
# the pcm process and the other process
# in the directories mentioned in the policy file
discard_set = set()
discard_set_other = set()
askuser_set = set()
askuser_set_other = set()


if args.filename is None or args.login_name is None:
    parser.print_help()
    exit()

#print args.filename
#print " ".join(args.program_args)
policy_dict = {}
regex_list = []
policy_values = ('askuser', 'keep', 'discard')
try:
    policy_file = open(args.filename, 'r')
    for line in policy_file:
        (filename, value) = line.split()
        value = value.strip()
        if filename[0] != '/' and filename[0] != '~':
            print 'Error in parsing the file path in the policy file'
            exit()
        if value not in policy_values:
            print 'pcm uses only askuser, keep, discard as policy values'
            exit()
        if filename in policy_dict:
            print 'Duplicate policies for the same file'
            exit()
        else:
            # Primitive shell expansion and some 
            # stuff for making regular expressions simpler
            if filename[0] == '~':
                filename = '/home/' + args.login_name + filename[1:]
            # This will make regular expression simpler some time in the 
            # future
            filename = filename.replace('*', '.*')
            #print filename
            policy_dict[filename] = value
    #print policy_dict

except IOError:
    print "Error reading policy file"
    exit()

# Change this to take the real user id
real_uid = 1000 #os.getresuid()[0]
login_name = pwd.getpwuid(os.getresuid()[0] )[0]
#print login_name

# Before forking make a snapshot of the root 
# subvolume and the home subvolume 
# It assumes that you have a subvolume for /home
# and that is how it is suppose to be if its not you 
# doing it wrong

subprocess.call(btrfs_create_root_snapshot)
subprocess.call(btrfs_create_home_snapshot)

# Fork 2 threads, 1 for actual program 
# and the other for the fatrace

pid = os.fork()
if not pid:
    os.setuid(real_uid)
    print 'Starting pcm process ...'
    child(args.program_args)
else:
    filename = id_generator()
    filename = '/tmp/' + filename
    #print filename
    fatrace_fork(login_name, pid, filename)
    try :
        pid = str(pid)
        f = open(filename, 'r')
	os.chmod(filename, stat.S_IREAD|stat.S_IWRITE)
    except IOError:
        print "Error opening the audit file"
        exit()


    for line in f:
        for key in policy_dict.keys():
            # regex for create as well
            search_regex = '.*\((.*)\):\s(CW|W)\s('  + key + ')'
                #print search_regex
                #print line
            m = re.search(search_regex, line)
                #print m
            if m is not None:
                if m.group(1) == pid:
                    if policy_dict[key] == 'discard':
                        discard_set.add(m.group(3))
                    else:
                        askuser_set.add(m.group(3))
                else:
                    if policy_dict[key] == 'discard':
                        discard_set_other.add(m.group(3))
                    else:
                        askuser_set_other.add(m.group(3))
                        
                #print m.group(2)
                #print m.group(3)
    #print askuser_set
    #print discard_set
    #print askuser_set_other
    #print discard_set_other
    
    askuser_set = askuser_set - askuser_set_other
    discard_set = discard_set - discard_set_other
    
    for discard_file in discard_set:
        try:
            snapshot_file = snapshot_file_path(discard_file)
	    if os.path.isfile(discard_file):
            	os.remove(discard_file)
	    if os.path.isfile(snapshot_file):
            	shutil.copy2(snapshot_file, discard_file)

        except OSError, why:
            print why
        except IOError, why:
            # Don't do anything
            pass
        
        
        
    # Snapshotting stuff over here
    for askuser_file in askuser_set:
        x = raw_input('Do you want to keep the file ' + askuser_file + ' [y/n]')
        if x == 'n':
            try:
                snapshot_file = snapshot_file_path(discard_file)
                if os.path.isfile(askuser_file):
		    os.remove(askuser_file)
		if os.path.isfile(snapshot_file):
                    shutil.copy2(snapshot_file, discard_file)
            except OSError, why:
                print why
            except IOError, why:
                # Don't do anything
                pass
        
    subprocess.call(btrfs_delete_root_snapshot)
    subprocess.call(btrfs_delete_home_snapshot)
    try:
	# TODO Remove the temp file
        os.remove(filename)
    except OSError, why:
        print why
        exit()
        



    