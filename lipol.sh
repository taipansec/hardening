#!/bin/sh

# Author : TAIPANSEC

bred='\033[1;31m'
bgreen = '\033[1;32m'
Color_Off='\033[0m'

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
echo -e "$Color_Off"

banner()
{
  echo "+------------------------------------------+"
  printf "| %-40s |\n" "`date`"
  echo "|                                          |"
  printf "|`tput bold` %-40s `tput sgr0`|\n" "$@"
  echo "+------------------------------------------+"
}

function status() {
    rep = $1
    if [[ $rep =~ "ok" ]]
    then
        echo -e "$bgreen"; echo "The current setting meets the CIS requirements"; echo -e "$Color_Off"
    else
        echo -e "$bred"; echo "The configuration doesn't meet CIS the requirements"; echo "Actual value is: $arg1"; echo -e "$Color_Off"
    fi
}

function condchk() {
    op = $1
    arg2 = $2
    arg3 = ${3:-}

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
        if [ -z "$arg2" ]
        then
            status "ok"
        else
            status "nok"
        fi
        ;;
    esac
}

function fscheck() {
    banner "File system configuration chapter"

    echo '1.1.1.1 Ensure mounting of cramfs filesystems is disabled'
    mpcramfs = $(modprobe -n -v cramfs | grep -E '(cramfs|install)')
    re = "install /bin/true"
    condchk 'eq' $mpcramfs $re
    lmcramfs = $(lsmod | grep cramfs)
    condchk 'null' $lmcramfs
}

