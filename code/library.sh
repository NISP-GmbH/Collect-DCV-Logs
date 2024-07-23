welcomeMessage()
{
    echo "This script will collect important logs to help you to find problems in DCV server and eventually additional components."
    echo -e "${GREEN}By default the script will not restart any service without your approval. So if you do not agree when asked, this script will collect all logs without touch in any running service.${NC}"
    echo "Answering yes to those answers can help the support to troubleshoot the problem."
    echo "If is possible, please execute this script inside of Xorg session (GUI session), so we can collect some useful informations."
    echo -e "${GREEN}We strongly recommend that you have the follow packages installed: nice-dcv-gl, nice-dcv-gltest and nice-xdcv.${NC}"
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
    echo "Checking your Linux distribution..."
    echo "Note: If you know what you are doing, please use --force option to avoid our Linux Distro compatibility test."

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
                echo "Your Debian Based Linux distro is not supported."
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
    for new_dir in kerberos_conf pam_conf sssd_conf nsswitch_conf dcvgldiag nvidia_info warnings xorg_log xorg_conf dcv_conf dcv_log os_info os_log journal_log hardware_info gdm_log gdm_conf
    do
        sudo mkdir -p ${temp_dir}/$new_dir
    done
}

containsVersion() {
    local string="$1"
    local version="$2"
    [[ "$string" =~ (\.|-)[0-9]+\.el$version([._]|$) || 
       "$string" =~ \.el$version([._]|$) || 
       "$string" =~ -$version\. || 
       "$string" == *".$version" ||
       "$string" =~ \.module\+el$version ]]
}

checkPackagesVersions()
{
    echo "Checking packages versions... depending of your server it can take up to 2 minutes..."
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
                echo "Package $package version $version_release might not be compatible with EL$redhat_distro_based_version" >> ${target_dir}/packages_not_os_compatible
            fi
        done
    fi

    if [[ "$ubuntu_distro" == "true" ]]
    then
        dcv_packages=(
        "nice-dcv-gl"
        "nice-dcv-gltest"
        "nice-dcv-server"
        "nice-dcv-session-manager-agent"
        "nice-dcv-session-manager-broker"
        "nice-dcv-simple-external-authenticator"
        "nice-dcv-web-viewer"
        "nice-xdcv"
        )

    for package in "${dcv_packages[@]}"
    do
        if dpkg -s "$package" &> /dev/null
        then
            version=$(dpkg-query -W -f='${Version}' "$package")
            
            year=$(echo "$version" | cut -d'.' -f1)
            
            if [[ "$ubuntu_version" == "20.04" ]]; then
                min_year=2020
            elif [[ "$ubuntu_version" == "22.04" ]]; then
                min_year=2022
            else
                min_year=$(($(date +%Y) - 1))  # Default to last year for unknown Ubuntu versions
            fi

            if [[ "$year" -lt "$min_year" ]]; then
                echo "Warning: $package version $version might be too old for Ubuntu $ubuntu_version. Expected minimum year: $min_year" >> "${target_dir}/dcv_packages_version_mismatch"
            else
                echo "Note: $package version $version appears to be compatible with Ubuntu $ubuntu_version" >> "${target_dir}/dcv_packages_version_info"
            fi
        else
            echo "Package $package is not installed" >> "${target_dir}/dcv_packages_not_installed"
        fi
    done
    fi
}

getEnvironmentVars()
{
    echo "Collecting environment variables..."
    target_dir="${temp_dir}/os_info/"
    env > ${target_dir}/env_command
    env > sort > ${target_dir}/env_sorted_command
    printenv > ${target_dir}/printenv_command
}

getPamData()
{
    echo "Collecting all PAM relevant info..."
    target_dir="${temp_dir}/pam_conf/"

    if [ -d /etc/pam.d ]
    then
        sudo cp -r /etc/pam.d ${target_dir}
    fi
}

getKerberosData()
{
    echo "Collecting all Kerberos relevant info..."
    target_dir="${temp_dir}/kerberos_conf/"

    if [ -f /etc/krb5.conf ]
    then
        sudo cp /etc/krb5.conf $target_dir
    fi
}

getSssdData()
{
    echo "Collecting all SSSD relevant info..."
    target_dir="${temp_dir}/sssd_conf/"

    if [ -d /etc/sssd/ ]
    then
        sudo cp -r /etc/sssd ${target_dir}
    fi

    detect_sssd=$(sudo ps aux | egrep -i 'sssd')
    if [[ "${detect_sssd}x" != "x" ]]
    then
        echo "$detect_sssd" > $temp_dir/warnings/sssd_is_running
    fi

    target_dir="${temp_dir}/sssd_log"
    if [ -f /var/log/sssd ]
    then
        sudo cp -r /var/log/sssd ${target_dir}
    fi
}

getNsswitchData()
{
    echo "Collecting all NSSwitch relevant info..."
    target_dir="${temp_dir}/nsswitch_conf/"

    if [ -d /etc/nsswitch.conf ]
    then
        sudo cp /etc/nsswitch.conf ${target_dir}/
    fi
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

    sudo systemctl is-active gdm.service > "${target_dir}/active_status"
    sudo systemctl is-enabled gdm.service > "${target_dir}/enabled_status"
    sudo systemctl status gdm.service > "${target_dir}/current_status"
    sudo journalctl -u gdm.service > "${target_dir}/gdm_journal"
    
    if pgrep -x "gdm" > /dev/null
    then
        echo "GDM process is running" > "${target_dir}/gdm_process_status"
    else
        echo "GDM process is not running" > "${target_dir}/gdm_process_status"
        echo "GDM process is not running" > "${temp_dir}/warnings/gdm_is_not_running"
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
    echo -e "${GREEN}Do you agree with DCV service restart?${NC}"
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

runDcvgldiag()
{
    target_dir="${temp_dir}/dcvgldiag/"

    if command -v dcvgldiag > /dev/null 2>&1
    then
        user_answer="no"
        echo "The script want to reboot the Xorg to collect some info after service reboot."
        echo -e "${GREEN}Do you agree with X service restart?${NC}"
        echo "If is possible, please write \"yes\". Any other response, or empty response, will me considered as no."
        read user_answer

        if [[ "$user_answer" == "yes" ]]
        then
            sudo systemctl isolate multi-user.target
            sudo dcvgladmin disable
            sudo dcvgladmin enable
            sudo systemctl isolate graphical.target

            sudo dcvgldiag -l ${target_dir}/dcvgldiag.log &> /dev/null
            
            if cat ${target_dir}/dcvgldiag.log | egrep -iq "Test Result: ERROR"
            then
                dcvgldiag_errors_count=$(egrep -ic "Test Result: ERROR" ${target_dir}/dcvgldiag.log)
                echo "found >>> $dcvgldiag_errors_count <<< tests with error result" > ${temp_dir}/warnings/dcvgldiag_found_${dcvgldiag_errors_count}_errors
            fi
        else
            echo "user not approved to run dcvgldiag" > ${target_dir}/dcvgldiag_not_executed
        fi
    else
        echo "dcvgldiag not installed" > ${temp_dir}/warnings/dcvgldiag_not_installed
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
    echo "DISPLAY var content: >>> $DISPLAY <<<" > ${target_dir}/display_content_var
    if [[ "${DISPLAY}x" == "x" ]]
    then
        echo "DISPLAY is empty" > ${temp_dir}/warnings/display_var_is_empty
    fi

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
    else
        echo "X not found, X -configure can not be executed" > ${temp_dir}/warnings/X_was_not_found
    fi

    detect_wayland=$(sudo ps aux | egrep -i 'wayland')
    if [[ "${detect_wayland}x" != "x" ]]
    then
        echo "$detect_wayland" > ${temp_dir}/warnings/wayland_is_running
    fi

    XAUTH=$(ps aux | grep "/usr/bin/X.*\-auth" | grep -v grep | sed -n 's/.*-auth \([^ ]\+\).*/\1/p')
    x_display=$(sudo ps aux | egrep '(X|Xorg|Xwayland)' | awk '{for (i=1; i<=NF; i++) if ($i ~ /^:[0-9]+$/) print $i}')
    if [[ "${x_display}x" == "x" ]]
    then
        echo "not possible to execute xrandr: display not found" > ${target_dir}/xrandr_can_not_be_executed
    else
        DISPLAY=${x_display} xrandr > ${target_dir}/xrandr

        if [ -n "$XAUTH" ]; then
            sudo DISPLAY=${x_display} XAUTHORITY="$XAUTH" glxinfo | grep -i "opengl.*version" > "${target_dir}/opengl_version" 2>"${target_dir}/opengl_possible_errors"
        else
            sudo DISPLAY=${x_display} glxinfo | grep -i "opengl.*version" > "${target_dir}/opengl_version" 2>"${target_dir}/opengl_possible_errors"
        fi
    fi

}
