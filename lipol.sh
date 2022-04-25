#!/bin/bash

# Author : TAIPANSEC

bred='\033[1;31m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
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

    if [[ $rep =~ "ok" ]]
    then
        echo -e "$bgreen"; echo "The current setting meets the CIS requirements"; echo -e "$color_off"
    else
        echo -e "$bred"; echo "The configuration doesn't meet CIS the requirements"; echo "Actual value is: $rep"; echo -e "$color_off"
    fi
}

function condchk() {
    op=$1
    arg2=$2
    arg3=${3:-}

    case $op in
    'eq')
        if [[ $arg2 =~ $arg3 ]]
        then
            status "ok"
        else
            status "nok"
        fi
        ;;
    'null')
        if [[ -n "$arg2" ]]
        then
            status "ok"
        else
            status "nok"
        fi
        ;;
    'notnull')
        if [[ -n "$arg2" ]]
        then
            status "nok"
        else
            status "ok"
        fi
        ;;
    esac
}

function echotitle() {
    title=$1
    echo -e "$byellow"; echo "$title"; echo -e "$color_off"
}
function fsmount() {
    title=$1
    fstype=$2
    re="install /bin/true"
    mpcheck="Checking via modprobe for: $fstype"
    lmcheck="Checking via lsmod for: $fstype"

    echotitle "$title"
    echo $mpcheck
    mp=$(modprobe -n -v $fstype | grep -E '($fstype|install)')
    condchk 'eq' "$mp" "$re'
    echo $lmcheck
    lm=$(lsmod | grep $fstype)
    condchk 'null' "$lm"
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
    mt=$(findmnt -n /tmp)
    grp=$(echo $mt | grep -E '^(/tmp\s*tmpfs\s*tmpfs\s*rw,nosuid,nodev,noexec)')
    condchk 'notnull' "$grp"
}

fscheck