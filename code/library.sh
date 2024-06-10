welcomeMessage()
{
    echo "This script will collect important logs to help you to find problems in DCV server and eventually additional components."
    echo "By default the script will not restart any service without your approval. So if you do not agree when asked, this script will collect all logs without touch in any running service."
    echo "Answering yes to those answers can help the support to troubleshoot the problem."
    echo "If is possible, please execute this script inside of Xorg session (GUI session), so we can collect some useful informations."
    echo "To start collecting the logs, press enter or ctrl+x to quit."
    read p
}

askToEncrypt()
{
    echo "The file >>> $compressed_file_name <<< was created and is ready to send to support."
    echo "If you want to encrypt the file with password, please use this command:"
    echo "gpg -c $compressed_file_name"
    echo "And set a password to open the file. Then send the file to us and send the password in a secure way."
    echo "To decrypt and extract, the command is:"
    echo "gpg -d ${compressed_file_name}.gpg | tar xzvf -"
    echo "Encrypting is not mandatory to send to the support."
}

compressLogCollection()
{
    tar czf $compressed_file_name $temp_dir
}

removeTempDirs()
{
    rm -rf $temp_dir
}

createTempDirs()
{
    echo "Creating temp dirs structure to store the data..."
    for new_dir in xorg_log xorg_conf dcv_conf dcv_log os_info os_log journal_log hardware_info
    do
        sudo mkdir -p ${temp_dir}/$new_dir
    done
}

getHwInfo()
{
    target_dir="${temp_dir}/hardware_info/"

    if command -v lshw > /dev/null 2>&1
    then
        sudo lshw > ${target_dir}/lshw_hardware_info.txt
    else
        echo "lshw not found" > ${target_dir}/not_found_lshw
    fi

    if command -v lscpu > /dev/null 2>&1
    then
        sudo lscpu  > ${target_dir}/lscpu_hardware_info.txt
    else
        echo "lscpu not found" > ${target_dir}/not_found_lscpu
    fi

    if command -v dmidecode > /dev/null 2>&1
    then
        sudo dmidecode > ${target_dir}/dmidecode        
    else
        echo "dmidecode not found" > ${target_dir}/not_found_dmidecode 

    fi
}

getDcvDataAfterReboot()
{
    user_answer="no"
    echo "The script want to reboot the dcvserver to collect some info after service reboot."
    echo "Do you agree with DCV service restart?"
    echo "If is possible, please write \"yes\". Any other response, or empty response, will me considered as no."
    read user_answer
    target_dir="${temp_dir}/dcv_log/after_reboot/"
    mkdir -p $target_dir

    if echo $user_answer | egrep -iq "yes"
    then
        sudo systemctl restart dcvserver
    
        if [ -d /var/log/dcv ]
        then
            sudo cp -r /var/log/dcv ${target_dir}
        else
            echo "not found" > $target_dir/var_log_dcv_not_found
            sudo journalctl -n 5000 > ${target_dir}/journal_last_5000_lines.log
            sudo journalctl --no-page | grep -i selinux > ${target_dir}/selinux_log_from_journal
            sudo journalctl --no-page | grep -i apparmor > ${target_dir}/apparmor_log_from_journal
        fi 
    else
        echo "dcv reboot test not executed" > ${target_dir}/after_reboot/dcv_reboot_test_not_executed
    fi
}

getDcvData()
{
    echo "Collecting all DCV relevant data..."
    target_dir="${temp_dir}/dcv_conf/"

    if [ -d /etc/dcv ]
    then
        sudo cp -r /etc/dcv $target_dir
    else
        echo "not found" > $target_dir/etc_dcv_dir_not_found
    fi    

    target_dir="${temp_dir}/dcv_log/"
    
    if [ -d /var/log/dcv ]
    then
        sudo cp -r /var/log/dcv $target_dir
    else
        echo "not found" > $target_dir/var_log_dcv_not_found
    fi
}

getOsData()
{
    echo "Collecting all Operating System relevant data..."
    target_dir="${temp_dir}/os_info/"
    sudo uname -a > $target_dir/uname_-a

    if command -v lsb_release > /dev/null 2>&1
    then
        sudo lsb_release -a > $target_dir/lsb_release_-a
    else
        echo "lsb_release not found" > $target_dir/not_found_lsb_release
    fi

    if command -v getenforce > /dev/null 2>&1
    then
        sudo getenforce > $target_dir/getenforce_result
    fi

    if [ -f /etc/issue ]
    then
        sudo cp /etc/issue $target_dir 
    fi

    if [ -f /etc/debian_version ]
    then
        sudo cp /etc/debian_version $target_dir
    fi

    if [ -f /etc/redhat-release ]
    then
        sudo cp /etc/redhat-release $target_dir
    fi

    if [ -f /etc/centos-release ]
    then
        sudo cp /etc/centos-release $target_dir
    fi

    if [ -f /usr/lib/apt ]
    then
        sudo dpkg -a > ${target_dir}/deb_packages_list
    fi

    if [ -f /usr/bin/rpm ]
    then
        sudo rpm -qa > ${target_dir}/rpm_packages_list
    fi

    target_dir="${temp_dir}/os_log/"
    sudo cp /var/log/dmesg* $target_dir
    sudo cp /var/log/kern* $target_dir
    sudo cp /var/log/auth* $target_dir
    sudo cp /var/log/syslog* $target_dir
    sudo cp -r /var/log/audit* $target_dir > /dev/null 2>&1

    target_dir="${temp_dir}/journal_log"
    sudo journalctl -n 5000 > ${target_dir}/journal_last_5000_lines.log
    sudo journalctl --no-page | grep -i selinux > ${target_dir}/selinux_log_from_journal
    sudo journalctl --no-page | grep -i apparmor > ${target_dir}/apparmor_log_from_journal
}

getXorgData()
{
    echo "Collecting all Xorg relevant data..."
    target_dir="${temp_dir}/xorg_log/"
    sudo cp -r /var/log/Xorg* $target_dir
    
    target_dir="${temp_dir}/xorg_conf/"
    if [ -d /etc/X11 ]
    then
        sudo cp -r /etc/X11 $target_dir
    fi

    if [ -d /usr/share/X11 ]
    then
        sudo cp -r /usr/share/X11 $target_dir
    fi

    if command -v X > /dev/null 2>&1
    then
        sudo X -configure > ${target_dir}/xorg.conf.configure.stdout 2> ${target_dir}xorg.conf.configure.stderr
    fi

    x_display=$(sudo ps aux | egrep '(X|Xorg|Xwayland)' | awk '{for (i=1; i<=NF; i++) if ($i ~ /^:[0-9]+$/) print $i}')
    if [[ "${x_display}x" == "x" ]]
    then
        echo "not possible to execute xrandr: display not found" > ${target_dir}/xrandr_can_not_be_executed
    else
        DISPLAY=${x_display} xrandr > ${target_dir}/xrandr
    fi
}
