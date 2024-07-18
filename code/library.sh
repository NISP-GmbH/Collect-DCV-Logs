welcomeMessage()
{
    echo "This script will collect important logs to help you to find problems in DCV server and eventually additional components."
    echo "By default the script will not restart any service without your approval. So if you do not agree when asked, this script will collect all logs without touch in any running service."
    echo "Answering yes to those answers can help the support to troubleshoot the problem."
    echo "If is possible, please execute this script inside of Xorg session (GUI session), so we can collect some useful informations."
    echo "To start collecting the logs, press enter or ctrl+c to quit."
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

checkLinuxDistro()
{
    echo "If you know what you are doing, please use --force option to avoid our Linux Distro compatibility test."

    if [ -f /etc/redhat-release ]
    then
        release_info=$(cat /etc/redhat-release)

        if echo $release_info | egrep -iq centos
        then
            redhat_distro_based="true"
        else
            if echo $release_info | egrep -iq almalinux
            then
                redhat_distro_based="true"
            else
                if echo $release_info | egrep -iq rocky
                then
                    redhat_distro_based="true"
                fi
            fi
        fi

        if [[ "${redhat_distro_based}" == "true" ]]
        then
            if echo "$release_info" | egrep -iq stream
            then
                redhat_distro_based_version=$(cat /etc/redhat-release  |  grep -oE '[0-9]+')
            else
                redhat_distro_based_version=$(echo "$release_info" | grep -oE '[0-9]+\.[0-9]+' | cut -d. -f1)
            fi

            if [[ ! $redhat_distro_based_version =~ ^[789]$ ]]
            then
                echo "Your RedHat Based Linux distro version..."
                cat /etc/redhat-release
                echo "is not supported. Aborting..."
                exit 18
            fi
        else
            echo "Your RedHat Based Linux distro..."
            cat /etc/redhat-release
            echo "is not supported. Aborting..."
            exit 19
        fi
    else
        if [ -f /etc/debian_version ]
        then
            if cat /etc/issue | egrep -iq "ubuntu"
            then
                ubuntu_distro="true"
                ubuntu_version=$(lsb_release -rs)
                ubuntu_major_version=$(echo $ubuntu_version | cut -d '.' -f 1)
                ubuntu_minor_version=$(echo $ubuntu_version | cut -d '.' -f 2)
                if ( [[ $ubuntu_major_version -lt 18 ]] || [[ $ubuntu_major_version -gt 24  ]] ) && [[ $ubuntu_minor_version -ne 04 ]]
                then
                    echo "Your Ubuntu version >>> $ubuntu_version <<< is not supported. Aborting..."
                    exit 20
                fi
            else
                echo "Your Debian Based Linxu distro is not supported."
                echo "Aborting..."
                exit 21
            fi
        else
            echo "Not able to find which distro you are using."
            echo "Aborting..."
            exit 22
        fi
    fi
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
    for new_dir in nvidia_info warnings xorg_log xorg_conf dcv_conf dcv_log os_info os_log journal_log hardware_info gdm_log gdm_conf
    do
        sudo mkdir -p ${temp_dir}/$new_dir
    done
}

containsVersion() {
    local string="$1"
    local version="$2"
    [[ "$string" =~ \.el$version[._] || "$string" =~ -$version\. || "$string" == *".$version" ]]
}

checkPackagesVersions()
{
    echo "Checking packages versions..."
    checkLinuxDistro
    target_dir="${temp_dir}/warnings/"

    if [[ "$ubuntu_distro" == "false" ]]
    then
        if [[ "$redhat_distro_based" == "false" ]]
        then
            echo "OS not supported" > ${target_dir}/os_not_supported
        fi
    fi

    if [[ "$redhat_distro_based" == true ]]
    then
        rpm -qa --qf "%{NAME} %{VERSION}-%{RELEASE}\n" | while read -r package version_release
        do
            if ! containsVersion "$version_release" "$redhat_distro_based_version"
            then
                for other_version in 7 8 9;
                do
                    if [ "$other_version" != "$redhat_distro_based_version" ] && containsVersion "$version_release" "$other_version"
                    then
                        echo "Package $package version $version_release might be from EL$other_version" >> ${target_dir}/packages_not_os_compatible
                    ibreak
                    fi
                done
            fi
        done
    fi

    if [[ "$ubuntu_distro" == "true" ]]
    then
        sudo dpkg -l | awk '/^ii/ {print $2}' | while read package
        do
            version=$(dpkg -s "$package" | grep '^Version:' | awk '{print $2}')
    
            if ! echo "$version" | grep -q "$ubuntu_version"
            then
                if echo "$version" | grep -qE '([0-9]{2}\.[0-9]{2})'
                then
                    echo "Package $package version $version might be from a different Ubuntu version" >> ${target_dir}/packages_not_os_compatible
                fi
            fi
        done
    fi
}

getEnvironmentVars()
{
    echo "Collecting envirnment variables..."
    target_dir="${temp_dir}/os_info/"
    env > ${target_dir}/env_command
    env > sort > ${target_dir}/env_sorted_command
    printenv > ${target_dir}/printenv_command
}

getGdmData()
{
    echo "Collecting all GDM relevant info..."
    target_dir="${temp_dir}/gdm_log/"
    if [ -f /var/log/gdm ]
    then
        sudo cp -r /var/log/gdm $target_dir
    fi

    if [ -f /var/log/gdm3 ]
    then
        sudo cp -r /var/log/gdm3 $target_dir
    fi

    target_dir="${temp_dir}/gdm_conf/"
    if [ -f /etc/gdm/ ]
    then
        sudo cp -r /etc/gdm $target_dir
    fi
}

getHwData()
{
    echo "Collecting all Hardware relevant info..."
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
        echo "dcv reboot test not executed" > ${target_dir}/dcv_reboot_test_not_executed
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

getNvidiaInfo()
{
    target_dir="${temp_dir}/nvidia_info/"
    if command -v nvidia-smi > /dev/null 2>&1
    then
        nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,pstate,pcie.link.gen.max,pcie.link.gen.current,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.free,memory.used --format=csv -l 5 -f ${target_dir}/nvidia_query
        nvidia-smi &> ${target_dir}/nvidia-smi_command
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
    sudo cp /var/log/dmesg* $target_dir > /dev/null 2>&1
    sudo cp /var/log/messages* $target_dir > /dev/null 2>&1
    sudo cp /var/log/kern* $target_dir > /dev/null 2>&1
    sudo cp /var/log/auth* $target_dir > /dev/null 2>&1
    sudo cp /var/log/syslog* $target_dir > /dev/null 2>&1
    sudo cp -r /var/log/audit* $target_dir > /dev/null 2>&1
    sudo cp -r /var/log/secure* $target_dir > /dev/null 2>&1
    sudo cp -r /var/log/boot* $target_dir > /dev/null 2>&1
    sudo cp -r /var/log/kdump* $target_dir > /dev/null 2>&1

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

    sudo DISPLAY=:0 XAUTHORITY=$(ps aux | grep "X.*\-auth" | grep -v grep | sed -n 's/.-auth \([^ ]\+\)./\1/p') glxinfo | grep -i "opengl.*version" > ${target_dir}/opengl_version
}
