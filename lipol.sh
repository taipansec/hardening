#!/bin/bash

# Author : TAIPANSEC

bred='\033[1;31m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
bwhite='\033[1;37m'
color_off='\033[0m'

echo -e "$bred"
echo '
                .:~!77??????77!~:.                
            :~7?JJYYYYYYJJYYYYYYJJ?7~:            
         :!?JYYYJJJJJJJJJJJJJJJJYYYYYJ?!:         
       ^7JYYJJJJJJJJJJJJJJJJJJYJ??JYJJYYJ7^       
     :7YYJJJJJJJJJJJYYYYYYYYYJ~.  .~JJJJJYY7:     
    ~JYJJJJJJJJJYYJJ?7!~~~~!??      JYJJJJJYJ~    
   7YJJJJJJJJJYY?7Y!         77^::^7JJJJJJJJJY7   
  7YJJJJJJJJJY?^  ~J~.::^^::. :^~~~?YJJJJJJJJJY7  
 ~YJJJJJJJJJY!     7YJJYYYYJJ7^     !YJJJJJJJJJY~ 
.JJJJJJYYYYY~    ^JYJJJJJJJJJYYJ^    ~YJJJJJJJJJJ.
~YJJJJJ7~~7J^   ~YYJJJJJJJJJJJJYY~    7YJJJJJJJJY~
!YJJJJ:    .J^ .JYJJJJJJJJJJJJJJYJ~~~~7YJJJJJJJJY!
!YJJJJ:    .J^ .JYJJJJJJJJJJJJJJYJ~~~~7YJJJJJJJJY!
~YJJJJJ7~~7J^   ~YYJJJJJJJJJJJJYY~    7YJJJJJJJJY~
.JJJJJJYYYYY~    ^JYJJJJJJJJYYYJ^    ~YJJJJJJJJJJ.
 ~YJJJJJJJJJY~     7YJJYYYYJJ7^     !YJJJJJJJJJY~ 
  7YJJJJJJJJJY?^  ^J~.::^^::. :^~~~?YJJJJJJJJJY7  
   7YJJJJJJJJJYY?7Y!         77^::^7JJJJJJJJJY7   
    ~JYJJJJJJJJJYYJJ?7!~~~~!?J      JYJJJJJYJ~    
     :7YYJJJJJJJJJJJYYYYYYYYYJ~.  .~JJJJJYY7:     
       ^7JYYJJJJJJJJJJJJJJJJJJYJ??JYJJYYJ7^       
         :!?JYYYJJJJJJJJJJJJJJJJYYYYYJ?!:         
            :~7?JJYYYYYYJJYYYYYYJJ?7~:            
                .:~!77??????77!~:.                


UBUNTU SERVER 20.04 - CIS L1 COMPLIANCY CHECKER
Author: TAIPANSEC
'
echo -e "$color_off"

banner()
{
  echo "+------------------------------------------+"
  printf "| %-40s |\n" "`date`"
  echo "|                                          |"
  printf "|`tput bold` %-40s `tput sgr0`|\n" "$@"
  echo "+------------------------------------------+"
}

function status() {
    rep=$1
    retval=( ${2:-empty} )

    if [[ $rep == "ok" ]]
    then
        echo -e "$bgreen"; echo "The current setting meets the CIS requirements"; echo -e "$color_off"
    else
        echo -e "$bred"; echo "The configuration doesn't meet the CIS requirements"; echo "Actual value is: " | tr -d '\n'
        for n in $retval
        do
            echo -e "$bwhite"; echo "$n"; echo -e "$color_off"
        done
    fi
}

function condchk() {
    op=$1
    arg2=$2
    arg3=${3:-}

    case $op in
    'eq')
        if [[ "$arg2" == "$arg3" ]]
        then
            status "ok"
        else
            status "nok"
        fi
        ;;
    'null')
        if [ -n "$arg2" ]
        then
            status "nok" "$arg2"
        else
            status "ok"
        fi
        ;;
    'notnull')
        if [ -n "$arg2" ]
        then
            status "ok"
        else
            status "nok" "$arg2"
        fi
        ;;
    esac
}

function echotitle() {
    title=$1
    echo -e "$byellow"; echo "$title"; echo "-------------------------------------------------------------------------" | tr -d '\n'; echo -e "$color_off"
}

function fsmount() {
    title=$1
    fstype=$2
    re="install /bin/true"
    mpcheck="Checking via modprobe for: $fstype"
    lmcheck="Checking via lsmod for: $fstype"

    echotitle "$title"
    echo "$mpcheck" | tr -d '\n'
    mp=$(modprobe -n -v $fstype | grep -E '($fstype|install)')
    condchk 'eq' "$mp" "$re"
    echo "$lmcheck" | tr -d '\n'
    lm=$(lsmod | grep "$fstype")
    condchk 'null' "$lm"
}

function mntchk() {
    finder=$1
    param=$2
    fs=$3

    if [[ -n "$finder" ]]
    then
        igrep=$(echo $finder | grep -v $param)
        condchk 'null' "$igrep"
    else
        echo -e "$bwhite"; echo "$fs is not mounted" | tr -d '\n'; echo -e "$color_off"
        status "nok"
    fi
}

function fscheck() {
    banner "File system configuration chapter"

    fsmount "1.1.1.1 Ensure mounting of cramfs filesystems is disabled" "cramfs"
    fsmount "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled" "freevxfs"
    fsmount "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled" "jffs2"
    fsmount "1.1.1.4 Ensure mounting of hfs filesystems is disabled" "hfs"
    fsmount "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled" "hfsplus"
    fsmount "1.1.1.7 Ensure mounting of udf filesystems is disabled" "udf"

    echotitle "1.1.2 Ensure /tmp is configured"
    tmp=$(findmnt -n /tmp)
    grp=$(echo $tmp | grep -E '^(/tmp\s*tmpfs\s*tmpfs\s*rw)')
    condchk 'notnull' "$grp"
    echotitle "1.1.3 Ensure nodev option set on /tmp partition"
    mntchk "$tmp" "nodev" "/tmp"
    echotitle "1.1.4 Ensure nosuid option set on /tmp partition"
    mntchk "$tmp" "nosuid" "/tmp"
    echotitle "1.1.5 Ensure noexec option set on /tmp partition"
    mntchk "$tmp" "noexec" "/tmp"

    echotitle "1.1.6 Ensure /dev/shm is configured"
    shm=$(findmnt -n /dev/shm)
    grp=$(echo $shm | grep -E '^(/dev/shm\s*tmpfs\s*tmpfs\s*rw)')
    condchk 'notnull' "$grp"
    echotitle "1.1.7 Ensure nodev option set on /dev/shm partition"
    mntchk "$shm" "nodev" "/dev/shm"
    echotitle "1.1.8 Ensure nosuid option set on /dev/shm partition"
    mntchk "$shm" "nosuid" "/dev/shm"
    echotitle "1.1.9 Ensure noexec option set on /dev/shm partition"
    mntchk "$shm" "noexec" "/dev/shm"

    var=$(findmnt -n /var/tmp)
    echotitle "1.1.12 Ensure /var/tmp partition includes the nodev option"
    mntchk "$var" "nodev" "/var/tmp"
    echotitle "1.1.13 Ensure /var/tmp partition includes the nosuid option"
    mntchk "$var" "nosuid" "/var/tmp"
    echotitle "1.1.14 Ensure /var/tmp partition includes the noexec option"
    mntchk "$var" "noexec" "/var/tmp"

    home=$(findmnt -n /home)
    echotitle "1.1.18 Ensure /home partition includes the nodev option"
    mntchk "$home" "nodev" "/home"
    
    echotitle "1.1.19 Ensure nodev option set on removable media partitions"
    echo -e "$bgreen"; echo "Manual check - not applicable if no removable media are in use"; echo -e "$color_off"
    echotitle "1.1.20 Ensure nosuid option set on removable media partitions"
    echo -e "$bgreen"; echo "Manual check - not applicable if no removable media are in use"; echo -e "$color_off"
    echotitle "1.1.21 Ensure noexec option set on removable media partitions"
    echo -e "$bgreen"; echo "Manual check - not applicable if no removable media are in use"; echo -e "$color_off"

    echotitle "1.1.22 Ensure sticky bit is set on all world-writable directories"
    df=( $(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null) )
    condchk 'null' "$df"
}

fscheck