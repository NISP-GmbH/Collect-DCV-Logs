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

    if $force_flag
    then
        echo "Force flag is set"
        # fake info
        redhat_distro_based=true
        redhat_distro_based_version=8
        ubuntu_distro=true
        ubuntu_major_version=20
        ubuntu_minor_version=04
    else
        echo "Force flag is not set"

        if [ -f /etc/redhat-release ]
        then
            release_info=$(cat /etc/redhat-release)
            if echo $release_info | egrep -iq "(centos|almalinux|rocky|red hat|redhat)"
            then
                redhat_distro_based="true"
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
    for new_dir in kerberos_conf pam_conf sssd_conf nsswitch_conf dcvgldiag nvidia_info warnings xorg_log xorg_conf dcv_conf dcv_log os_info os_log journal_log hardware_info gdm_log gdm_conf xfce_conf xfce_log
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
                echo "Package $package version $version_release might not be compatible with EL$redhat_distro_based_version" >> ${target_dir}/packages_might_not_os_compatible
            fi
        done

        if cat ${target_dir}/packages_might_not_os_compatible | egrep -iq dcv
        then
            dcv_packages_not_compatible=$(cat ${target_dir}/packages_might_not_os_compatible | egrep -i dcv)
            echo "Found some DCV packages not compatible:" >> ${target_dir}/dcv_packages_not_os_compatible
            echo $dcv_packages_not_compatible >> ${target_dir}/dcv_packages_not_os_compatible
        fi
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
            
            if [[ "$ubuntu_version" == "20.04" ]]
            then
                min_year=2020
            elif [[ "$ubuntu_version" == "22.04" ]]
            then
                min_year=2022
            else
                min_year=$(($(date +%Y) - 1))  # Default to last year for unknown Ubuntu versions
            fi

            if [[ $year =~ ^[0-9]+$ ]]
            then
                if [[ "$year" -lt "$min_year" ]]
                then
                    echo "Warning: $package version $version might be too old for Ubuntu $ubuntu_version. Expected minimum year: $min_year" >> "${target_dir}/dcv_packages_version_mismatch"
                else
                    echo "Note: $package version $version appears to be compatible with Ubuntu $ubuntu_version" >> "${target_dir}/dcv_packages_version_info"
                fi
            else
                echo "Package $package is not installed" >> "${target_dir}/dcv_packages_not_installed"
            fi
        fi
    done
    fi
}

getEnvironmentVars()
{
    echo "Collecting environment variables..."
    target_dir="${temp_dir}/os_info/"
    env > ${target_dir}/env_command
    env | sort > ${target_dir}/env_sorted_command
    printenv > ${target_dir}/printenv_command

    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | while read -r user
    do
        USER_DIR="${target_dir}/users_environment_vars/$user"
        mkdir -p "$USER_DIR"
    
        pid=$(pgrep -u "$user" -n)
        env_file="$USER_DIR/env.txt"

        if [ -z "$pid" ]
        then
            echo "No running processes found for user $user" > ${USER_DIR}/env_file
            continue
        fi

        cat "/proc/$pid/environ" | tr '\0' '\n' >> "$env_file"
    done
}

getPamData()
{
    echo "Collecting all PAM relevant info..."
    target_dir="${temp_dir}/pam_conf/"

    if [ -d /etc/pam.d ]
    then
        sudo cp -r /etc/pam.d ${target_dir} > /dev/null 2>&1
    fi
}

getKerberosData()
{
    echo "Collecting all Kerberos relevant info..."
    target_dir="${temp_dir}/kerberos_conf/"

    if [ -f /etc/krb5.conf ]
    then
        sudo cp /etc/krb5.conf $target_dir > /dev/null 2>&1
    fi
}

getSssdData()
{
    echo "Collecting all SSSD relevant info..."
    target_dir="${temp_dir}/sssd_conf/"

    if [ -d /etc/sssd/ ]
    then
        sudo cp -r /etc/sssd ${target_dir} > /dev/null 2>&1
    fi

    detect_service=""
    detect_service=$(sudo ps aux | egrep -i '[s]ssd')
    if [[ "${detect_service}x" != "x" ]]
    then
        echo "$detect_service" > $temp_dir/warnings/sssd_is_running
    fi

    target_dir="${temp_dir}/sssd_log"
    if [ -f /var/log/sssd ]
    then
        sudo cp -r /var/log/sssd ${target_dir}> /dev/null 2>&1
    fi
}

getNsswitchData()
{
    echo "Collecting all NSSwitch relevant info..."
    target_dir="${temp_dir}/nsswitch_conf/"

    if [ -d /etc/nsswitch.conf ]
    then
        sudo cp /etc/nsswitch.conf ${target_dir}/ > /dev/null 2>&1
    fi
}

getXfceLog()
{
    echo "Collecting all XFCE relevant info..."
    target_dir="${temp_dir}/xfce_log/"

    sudo journalctl --no-page | egrep -i xfce >> ${target_dir}/journalctl_xfce_log
}

getGdmData()
{
    echo "Collecting all GDM relevant info..."
    target_dir="${temp_dir}/gdm_log/"
    if [ -f /var/log/gdm ]
    then
        sudo cp -r /var/log/gdm $target_dir > /dev/null 2>&1
    fi

    if [ -f /var/log/gdm3 ]
    then
        sudo cp -r /var/log/gdm3 $target_dir > /dev/null 2>&1
    fi

    sudo journalctl -u gdm.service > "${target_dir}/systemctl_gdm_journal"

    target_dir="${temp_dir}/gdm_conf/"
    if [ -f /etc/gdm/ ]
    then
        sudo cp -r /etc/gdm $target_dir > /dev/null 2>&1
    fi

    if [ -f /etc/gdm3/ ]
    then
        sudo cp -r /etc/gdm3 $target_dir > /dev/null 2>&1
    fi

    sudo systemctl is-active gdm.service > "${target_dir}/systemctl_active_status"
    sudo systemctl is-enabled gdm.service > "${target_dir}/systemctl_enabled_status"
    sudo systemctl status gdm.service > "${target_dir}/systemctl_current_status"
    
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
        sudo dmidecode > ${target_dir}/dmidecode 2>&1
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

        echo "Waiting 10 seconds before collect the new logs..."
        sleep 10
        if [ -d /var/log/dcv ]
        then
            sudo cp -r /var/log/dcv ${target_dir} > /dev/null 2>&1
        else
            echo "not found" > $target_dir/var_log_dcv_not_found
            sudo journalctl -n 15000 > ${target_dir}/journal_last_15000_lines.log
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
        sudo cp -r /etc/dcv $target_dir > /dev/null 2>&1
    else
        echo "not found" > $target_dir/etc_dcv_dir_not_found
    fi    

    target_dir="${temp_dir}/dcv_log/"
    
    if [ -d /var/log/dcv ]
    then
        sudo cp -r /var/log/dcv $target_dir > /dev/null 2>&1
    else
        echo "not found" > $target_dir/var_log_dcv_not_found
    fi

    if cat ${target_dir}/dcv/*.log.* | egrep -iq "killed by signal 11"
    then
        echo "Found dcv process being killed  with signal 11 (segmentation fault)" ${temp_dir}/warnings/dcv_logs_kill_signal_11_found
    fi

    if cat ${target_dir}/dcv/server* | egrep -iq ".*RLM Initialization.*failed.*permission denied.*13.*"
    then
        echo ">>> RLM Initialization failed: permission denied <<< message found in server.log files" ${temp_dir}/warnings/rlm_failed_permission_denied
    fi

    if cat ${target_dir}/dcv/server* | egrep -iq ".*client will not be allowed to connect.*"
    then
        echo ">>> client will not be allowed to connect <<< message found in server.log files" ${temp_dir}/warnings/client_will_not_be_allowed_to_connect
    fi

    if cat ${target_dir}/dcv/server* | egrep -iq ".*too many files open.*"
    then
        echo ">>> too many files open <<< message found in server.log files" ${temp_dir}/warnings/too_many_files_open
    fi

    if cat ${target_dir}/dcv/agent* | egrep -iq "DCV Viewer.*2022" 
    then
        cat ${target_dir}/dcv/agent* | egrep -iq "DCV Viewer.*2022" >> ${temp_dir}/warnings/found_dcv_viewer_2022
    fi

    if cat ${target_dir}/dcv/agent* | egrep -iq "DCV Viewer.*2023"
    then
        cat ${target_dir}/dcv/agent* | egrep -iq "DCV Viewer.*2023" >> ${temp_dir}/warnings/found_dcv_viewer_2023
    fi

    if [ -f /var/log/dcv/server.log ]
    then
        if cat /var/log/dcv/server.log | egrep -iq "No license for product"
        then
            echo "No license for product" > ${temp_dir}/warnings/dcv_not_found_valid_license
        fi
    fi

    if [ -f /etc/dcv/dcv.conf ]
    then
        if ! cat /etc/dcv/dcv.conf | egrep -iq "^no-tls-strict.*=.*true"
        then
            cat <<EOF >> ${temp_dir}/warnings/dcv_server_no-tls-strict_is_false
- no-tls-strict is not true"

please add:
[security]
no-tls-strict=true
EOF
        fi

        if ! cat /etc/dcv/dcv.conf | egrep -iq "^enable-quic-frontend.*=.*true"
        then
            cat << EOF >> ${temp_dir}/warnings/dcv_server_quic_not_enabled
- quic protocol is not enabled
- please add:
[connectivity]
enable-quic-frontend=true
enable-datagrams-display = always-off
EOF
        fi
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

            sudo dcvgldiag -l ${target_dir}/dcvgldiag.log > /dev/null 2>&1
            
            if cat ${target_dir}/dcvgldiag.log | egrep -iq "Test Result: ERROR"
            then
                dcvgldiag_errors_count=$(egrep -ic "Test Result: ERROR" ${target_dir}/dcvgldiag.log)
                echo "found >>> $dcvgldiag_errors_count <<< tests with error result" > ${temp_dir}/warnings/dcvgldiag_found_${dcvgldiag_errors_count}_errors
            fi

            if cat ${target_dir}/dcvgldiag.log | egrep -iq "Detected nouveau kernel module"
            then
                echo "Detected nouveau kernel module" > ${temp_dir}/warnings/nouveau_kernel_module_found
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
        timeout_seconds=20
        echo "Executing nvidia-smi special query. The test will take up to >>> $timeout_seconds <<< seconds."
        timeout $timeout_seconds nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,pstate,pcie.link.gen.max,pcie.link.gen.current,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.free,memory.used --format=csv -l 5 -f ${target_dir}/nvidia_query > /dev/null 2>&1
        echo "Executing nvidia-smi generic query. The test will take up to >>> $timeout_seconds <<< seconds."
        timeout $timeout_seconds nvidia-smi &> ${target_dir}/nvidia-smi_command
    fi
}

getOsData()
{
    echo "Collecting all Operating System relevant data..."
    target_dir="${temp_dir}/os_info/"
    sudo uname -a > $target_dir/uname_-a

    if command -v lsb_release > /dev/null 2>&1
    then
        sudo lsb_release -a > $target_dir/lsb_release_-a 2>&1
    else
        echo "lsb_release not found" > $target_dir/not_found_lsb_release
    fi

    if command -v getenforce > /dev/null 2>&1
    then
        sudo getenforce > $target_dir/getenforce_result 2>&1
        if cat $target_dir/getenforce_result | egrep -iq "enforcing"
        then
            echo "selinux is being enforced" > ${temp_dir}/warnings/selinux_is_enforced
        fi
    fi

    if [ -f /etc/issue ]
    then
        sudo cp /etc/issue $target_dir > /dev/null 2>&1
    fi

    if [ -f /etc/debian_version ]
    then
        sudo cp /etc/debian_version $target_dir > /dev/null 2>&1
    fi

    if [ -f /etc/redhat-release ]
    then
        sudo cp /etc/redhat-release $target_dir > /dev/null 2>&1
    fi

    if [ -f /etc/centos-release ]
    then
        sudo cp /etc/centos-release $target_dir > /dev/null 2>&1
    fi

    if [ -f /usr/lib/apt ]
    then
        sudo dpkg -a > ${target_dir}/deb_packages_list 2>&1
    fi

    if [ -f /usr/bin/rpm ]
    then
        sudo rpm -qa > ${target_dir}/rpm_packages_list 2>&1
    fi
    
    uptime > ${target_dir}/uptime 2>&1

    ps aux --forest > ${target_dir}/ps_aux_--forest 2>&1
    pstree -p > ${target_dir}/pstree 2>&1

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

    if [ -f $target_dir/dmesg ]
    then
        if egrep -iq "oom" $target_dir/dmesg > /dev/null 2>&1
        then
            cat $target_dir/dmesg | egrep -i "(oom|killed)" > ${temp_dir}/warnings/oom_killer_log_found_dmesg
        fi

        if egrep -iq "(segfault|segmentation fault)" $target_dir/dmesg > /dev/null 2>&1
        then
            cat $target_dir/dmesg | egrep -i "(segfault|segmentation fault)" >> ${temp_dir}/warnings/segmentation_fault_found
        fi
    fi

    if [ -f $target_dir/messages ]
    then
        if egrep -iq "oom" $target_dir/messages > /dev/null 2>&1
        then
            cat $target_dir/messages | egrep -i "(oom|killed)" > ${temp_dir}/warnings/oom_killer_log_found_messages
        fi

        echo "Checking for SELinux logs... if you have big log files, please wait for a moment."
        grep -i "selinux is preventing" $target_dir/messages* | grep -i "dcv" | while read -r line 
        do
            echo "$line" > ${temp_dir}/warnings/selinux_is_preventing_dcv
        done

        if egrep -iq "(segfault|segmentation fault)" $target_dir/messages > /dev/null 2>&1
        then
            cat $target_dir/messages | egrep -i "(segfault|segmentation fault)" >> ${temp_dir}/warnings/segmentation_fault_found
        fi

    fi

    target_dir="${temp_dir}/journal_log"
    sudo journalctl -n 15000 > ${target_dir}/journal_last_15000_lines.log 2>&1
    sudo journalctl --no-page | grep -i selinux > ${target_dir}/selinux_log_from_journal 2>&1
    sudo journalctl --no-page | grep -i apparmor > ${target_dir}/apparmor_log_from_journal 2>&1

    if journalctl --no-page | egrep -iq "(segfault|segmentation fault)" > /dev/null 2>&1
    then
        journalctl --no-page | egrep -i "(segfault|segmentation fault)" >> ${temp_dir}/warnings/segmentation_fault_found
    fi

}

getXorgData()
{
    echo "Collecting all Xorg relevant data..."
    target_dir="${temp_dir}/xorg_log/"
    sudo cp -r /var/log/Xorg* $target_dir > /dev/null 2>&1
    
    target_dir="${temp_dir}/xorg_conf/"
    echo "DISPLAY var content: >>> $DISPLAY <<<" > ${target_dir}/display_content_var 2>&1
    if [[ "${DISPLAY}x" == "x" ]]
    then
        echo "DISPLAY is empty" > ${temp_dir}/warnings/display_var_is_empty 2>&1
        echo "The user executing is >>> $USER <<<" >> ${temp_dir}/warnings/display_var_is_empty 2>&1
    fi

    if [ -d /etc/X11 ]
    then
        mkdir -p ${target_dir}/etc_X11
        sudo cp -r /etc/X11 $target_dir/etc_X11 > /dev/null 2>&1
    fi

    if [ -d /usr/share/X11 ]
    then
        mkdir -p ${target_dir}/usr_share_X11
        sudo cp -r /usr/share/X11 ${target_dir}/usr_share_x11 > /dev/null 2>&1
        echo "/usr/share/X11 was found, but usually is expected /etc/X11. Check the last Xorg.log to identify which one is being used" >> ${temp_dir}/warnings/usr_share_X11_exist__usually_expected_etc_x11 2>&1
    fi

    if ls /etc/X11/xorg.conf.d/*nvidia* &>/dev/null
    then
        echo "A nvidia config file was found in >>> /etc/X11/xorg.conf.d/*nvidia* <<<. It can cause issues in xorg.conf config file." >> ${temp_dir}/warnings/nvidia_xorgconf_possible_override 2>&1
    fi

    if ls /usr/share/X11/xorg.conf.d/*nvidia* &>/dev/null
    then
        echo "A nvidia config file was found in >>> /usr/share/X11/xorg.conf.d/*nvidia* <<<. It can cause issues in xorg.conf config file." >> ${temp_dir}/warnings/nvidia_xorgconf_possible_override 2>&1
    fi

    find /etc/X11 -type f -exec grep -l "OutputClass" {} + | xargs -I {} readlink -f {} >> ${temp_dir}/warnings/found_nvidia_output_class_files_possible_xorgconf_override 2> /dev/null
    find /usr/share/X11 -type f -exec grep -l "OutputClass" {} + | xargs -I {} readlink -f {} >> ${temp_dir}/warnings/found_nvidia_output_class_files_possible_xorgconf_override 2> /dev/null

    sed -i '/^$/d' ${temp_dir}/warnings/found_nvidia_output_class_files_possible_xorgconf_override 2> /dev/null
    if [ ! -s ${temp_dir}/warnings/found_nvidia_output_class_files_possible_xorgconf_override ]
    then
        rm -f ${temp_dir}/warnings/found_nvidia_output_class_files_possible_xorgconf_override
    fi

    output_dir="${target_dir}/xsession_files"
    mkdir -p "$output_dir"

    echo "Checking for all .xsession files... if you have a lot of users, please wait some extra time."
    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | while read -r user; do
    home_dir=$(getent passwd "$user" | cut -d: -f6)
    user_files=$(find "$home_dir" -maxdepth 1 -name ".xsession*" 2> /dev/null)

    if [ -n "$user_files" ]
    then
        user_dir="$output_dir/$user"
        mkdir -p "$user_dir"

        for file in $user_files
        do
            cp "$file" "$user_dir/"
        done
    fi
    done

    if command -v X > /dev/null 2>&1
    then
        if pgrep X > /dev/null
        then
            echo "X is currently running. Cannot execute X -configure." > "${temp_dir}/warnings/X_--configure_failed" 2>&1
        else
            timeout_seconds=10
            echo "Executing X -configure query. The test will take up to >>> $timeout_seconds <<< seconds"
            sudo timeout $timeout_seconds X -configure > "${target_dir}/xorg.conf.configure.stdout" 2> "${target_dir}/xorg.conf.configure.stderr"
        fi
    else
        echo "X not found, X -configure can not be executed" > ${temp_dir}/warnings/X_was_not_found 2>&1
    fi

    detect_service=""
    detect_service=$(sudo ps aux | egrep -i '[w]ayland' | egrep -v "tar.gz")
    if [[ "${detect_service}x" != "x" ]]
    then
        
        echo "$detect_service" > ${temp_dir}/warnings/wayland_is_running 2>&1
    fi

    XAUTH=$(sudo ps aux | grep "/usr/bin/X.*\-auth" | grep -v grep | sed -n 's/.*-auth \([^ ]\+\).*/\1/p')
    x_display=$(sudo ps aux | egrep '([X]|[X]org|[X]wayland)' | awk '{for (i=1; i<=NF; i++) if ($i ~ /^:[0-9]+$/) print $i}')
    if [[ "${x_display}x" == "x" ]]
    then
        echo "not possible to execute xrandr: display not found" > ${target_dir}/xrandr_can_not_be_executed 2>&1
    else
        if command -v xrandr > /dev/null 2>&1
        then
            DISPLAY=${x_display} xrandr > ${target_dir}/xrandr_stdout 2> ${target_dir}/xrandr_stderr
        fi

        if command -v glxinfo > /dev/null 2>&1
        then
            if [ -n "$XAUTH" ]
            then
                sudo -E DISPLAY=${x_display} XAUTHORITY="$XAUTH" glxinfo 2>"${target_dir}/opengl_errors" | grep -i "opengl.*version" > "${target_dir}/opengl_version"
            else
                sudo -E DISPLAY=${x_display} glxinfo 2>"${target_dir}/glxinfo_errors" | grep -i "opengl.*version" > "${target_dir}/opengl_version"
            fi
        fi
    fi
}
