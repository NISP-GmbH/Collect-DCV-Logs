doHtmlReport()
{
	cat << EOF >> ${dcv_report_dir_path}/html_head
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NISP Report</title>
    <style>
        :root {
            --critical-color: red;
            --info-color: green;
            --warning-color: yellow;
            --suggestion-color: cyan;
        }
        
        body {
            background-color: black;
            color: white;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Oxygen, Ubuntu, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        h1 {
            color: white;
            font-weight: 500;
            font-size: 1.75rem;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
        }
        
        header h1 {
            font-size: 2.25rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding-bottom: 0.75rem;
        }
        
        .report-section {
            border-left: 4px solid rgba(255, 255, 255, 0.2);
            padding: 0.5rem 0 0.5rem 1.5rem;
            margin-bottom: 2rem;
        }
        
        .critical {
            color: var(--critical-color);
            border-left-color: var(--critical-color);
        }
        
        .warning {
            color: var(--warning-color);
            border-left-color: var(--warning-color);
        }
        
        .info {
            color: var(--info-color);
            border-left-color: var(--info-color);
        }
        
        .status-keyword {
            font-weight: bold;
        }
        
        .suggestion {
            color: var(--suggestion-color);
            margin-top: 0.5rem;
        }
        
        a {
            color: var(--suggestion-color);
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        .support-info {
            margin: 1rem 0 2rem;
        }
    </style>
</head>
<body>
    <header>
        <h1>NISP DCV Server Report</h1>
        <div class="support-info">
            <p>If you need support:</p>
			<p> <a href="https://www.ni-sp.com/support/" target="_blank">https://www.ni-sp.com/support/</a></p>
        </div>
    </header>
EOF

	cat << EOF >> ${dcv_report_dir_path}/html_tail
</body>
</html>
EOF

	cat ${dcv_report_dir_path}/html_head > $dcv_report_html_path
	cat ${dcv_report_dir_path}/html_critical >> $dcv_report_html_path
	cat ${dcv_report_dir_path}/html_warning >> $dcv_report_html_path
	cat ${dcv_report_dir_path}/html_info >> $dcv_report_html_path
	cat ${dcv_report_dir_path}/html_tail >> $dcv_report_html_path
	rm -f ${dcv_report_dir_path}/html_*
}

command_exists()
{
    command -v "$1" &> /dev/null
}

byebyeMessage()
{
    echo -e "${GREEN}Thank you! ${NC}"
}

reportMessage()
{
	local message_type="$1"
	local message_text="$2"
	if [[ "$3" == "null" ]]
	then
		local log_file="${dcv_report_path}"
	else
		local log_file="${dcv_report_path} $3"
	fi
	local message_suggestion="$4"
	local recommended_links="$5"

	reportMessageWrite "${message_text}" "${log_file}" "${message_type}" "${message_suggestion}" "${recommended_links}"
	reportMessageWriteHtml "${message_text}" "null" "${message_type}" "${message_suggestion}" "${recommended_links}"
}

reportMessageWriteHtml()
{
	local message_text="$1"
	local log_file="$2"
    local message_type=$3
	local message_suggestion=$4
	local recommended_links=$5

	cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
    <div class="report-section ${message_type}">
        <h1><span class="status-keyword ${message_type}">$(echo "${message_type}" | tr '[:lower:]' '[:upper:]'):</span> ${message_text}</h1>
EOF

	if [[ "${message_suggestion}" != "null" ]]
	then
		cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
	        <p class="suggestion"><strong>SUGGESTION:</strong> $message_suggestion</p>
EOF
	fi

	if [[ "${recommended_links}" != "null" ]]
	then
		cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
        <p class="suggestion"><strong>Recommended links:</strong></p>
		<ul>
EOF
		for link_recommended in $recommended_links
		do
			cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
	<li><a href="${link_recommended}" target="_blank">${link_recommended}</a></li>
EOF
		done

		cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
		</ul>
EOF
	fi

	cat << EOF >> ${dcv_report_dir_path}/html_${message_type}
    </div>
EOF
}

reportMessageWrite()
{
	local message_text="$1"
	local log_file="$2"
    local message_type=$3
	local message_suggestion=$4
	local recommended_links=$5

	
    case $message_type in
        critical)
			echo -e "${dcv_report_separator}" | tee -a $log_file  > /dev/null
            echo -e "${RED}CRITICAL: ${message_text}${NC}" | tee -a $log_file
        ;;
        warning)
			echo -e "${dcv_report_separator}" | tee -a $log_file  > /dev/null
            echo -e "${YELLOW}WARNING: ${message_text}${NC}" | tee -a $log_file
        ;;
        info)
			echo -e "${dcv_report_separator}" | tee -a $log_file  > /dev/null
            echo -e "${GREEN}INFO: ${message_text}${NC}" | tee -a $log_file
        ;;
    esac
    
	if [[ "${message_suggestion}" != "null" ]]
	then
		echo -e "${BLUE}SUGGESTION: ${message_suggestion}${NC}" | tee -a $log_file > /dev/null
	fi

	if [[ "${recommended_links}" != "null" ]]
	then
		echo -e "Recommended links:" | tee -a $log_file > /dev/null
		for link_recommended in $recommended_links
		do
			echo "- $link_recommended" | tee -a $log_file > /dev/null
		done
	fi
}


welcomeMessage()
{
    echo "#################################################"
    echo -e "${GREEN}Welcome to NI SP DCV Installation Checker!${NC}"
    echo -e "Check all of our guides and tools: https://github.com/NISP-GmbH/Guides"
    echo "#################################################"
	echo -e "${GREEN}Notes:${NC}"
    echo -e "${GREEN}- The script will not restart any service.${NC}"
    echo -e "${GREEN}- If is possible, please execute this script inside of Xorg session (GUI session).${NC}"
    echo -e "${GREEN}- We strongly recommend that you have the follow packages installed:${NC}"
	echo -e "${GREEN}nice-dcv-gl (if you use GPU), nice-dcv-gltest and smartctl.${NC}"
    echo "#################################################"

	option_selected=""
	if [[ "$collect_log_only" == "false" && "$report_only" == "false" ]]
	then
		echo -e "${GREEN}Select which option do you want to proceed:${NC}"
		echo -e "${GREEN}(1)${NC} Create a report that will look for common issues"
		echo -e "${GREEN}(2)${NC} Collect relevant logs to send to NISP Support Team"
		echo -e "${GREEN}Please type 1 or 2:${NC}"
	    read option_selected

		if ! echo $option_selected | egrep -iq "^(1|2)$"
		then
			echo "Option >> $option_selected << invalid. Exiting..."
			exit 24	
		fi
	elif [[ "$collect_log_only" == "true" && "$report_only" == "false" ]]
	then
		option_selected="2"
	elif [[ "$collect_log_only" == "false" && "$report_only" == "true" ]]
	then
		option_selected="1"
	else
		# collect logs will always create the report
		collect_log_only=true
		report_only=false 
		option_selected="2"
	fi

	case $option_selected in
		1)
			echo -e "${GREEN}The report will be saved in the same directory of the script with the name >> $dcv_report_file_name << and >> $dcv_report_html_file_name <<.${NC}"
			report_only="true"
		;;
		2)
    		echo -e "${GREEN}In the end an encrypted file will be created, then it will be securely uploaded to NISP and a notification will be sent to NISP Support Team.${NC}"
    		echo "If you do not have internet acess when executing this script, you will have an option to store the file in the end."

    		echo "Write any text that will identify you for NISP Support Team. Can be e-mail, name, e-mail subject, company name etc."
		    read identifier_string
		;;
	esac
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
            if echo $release_info | egrep -iq "(centos|almalinux|rocky|red hat|redhat|oracle)"
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
                        echo "Your Ubuntu version >> $ubuntu_version << is not supported. Aborting..."
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

setupUsefulTools()
{
    if ! command_exists smartctl
    then
        if $ubuntu_distro
        then
            if command_exists apt-get
            then
                sudo apt-get update
                sudo apt-get install -y smartmontools
            fi
        fi

        if $redhat_distro_based
        then
            if command_exists dnf
            then
                sudo dnf install -y smartmontools
            elif command_exists yum
            then
                sudo yum install -y smartmontools
            fi
        fi
    fi
}

compressLogCollection()
{
	if $report_only
	then
		return
	fi

    tar czf $compressed_file_name $temp_dir
}

encryptLogCollection()
{
	if $report_only
	then
		return
	fi

    gpg --symmetric --cipher-algo AES256 --batch --yes --passphrase "${encrypt_password}" --output "${encrypted_file_name}"  "${compressed_file_name}"
}

uploadLogCollection()
{
	if $report_only
	then
		return
	fi

    echo -e "${GREEN}${BOLD}Securely${NC}${GREEN} uploading the file to NISP Support Team...${NC}"
    curl_response=$(curl -s -w "\n%{http_code}" -F "file=@${encrypted_file_name}" "${upload_url}")
    if [ $? -ne 0 ]
    then
        echo "Failed to upload the file!"
        exit 23
    else
        echo -e "\nUpload successful!"
        curl_http_body=$(echo $curl_response | cut -d' ' -f1)
        curl_http_status=$(echo $curl_response | cut -d' ' -f2)
        curl_filename=$(echo "$curl_http_body" | tr -d '\r\n')
        curl_response=$(curl -s -w "\n%{http_code}" -X POST --data-urlencode "encrypt_password=${encrypt_password}" --data-urlencode "curl_filename=${curl_filename}" --data-urlencode "identifier_string=${identifier_string}" "$notify_url")
        if [ $? -ne 0 ]
        then
            echo "Failed to notificate the NISP Support Team about the uploaded file. Please send an e-mail."
        else
            echo -e "${GREEN}NISP Support Team was notified about the file!${NC}"
        fi
    fi
}

removeTempFiles()
{
    echo "Cleaning temp files..."

	if [ -d $temp_dir ]
	then
		if $report_only
		then
			if [ -f $dcv_report_file_name ]
			then
				rm -f $dcv_report_file_name
				cp -a ${dcv_report_path} .
				cp -a ${dcv_report_html_path} .
				echo -e "${GREEN}#########################################################################${NC}"
				echo -e "${GREEN}#########################################################################${NC}"
				echo -e "${GREEN}The TXT report was saved in >> $dcv_report_file_name <<.${NC}"
				echo -e "${GREEN}To read with ${RED}co${YELLOW}lo${BLUE}rs ${GREEN}you can use:${NC}"
				echo "less -R $dcv_report_file_name"
				echo -e "${GREEN}The HTML report was saved in >> $dcv_report_html_file_name <<.${NC}"
				echo -e "${GREEN}#########################################################################${NC}"
				echo -e "${GREEN}#########################################################################${NC}"
			fi
		fi
		rm -rf $temp_dir
	fi

	if [ -f $encrypted_file_name ]
	then
		rm -f $encrypted_file_name
	fi

	if ! $report_only
	then
	    echo -e "${GREEN}Do you want to delete the ${compressed_file_name}?${NC}"
	    echo "If you have no internet to upload the file, you can manually send to NISP Support Team."
	    echo "Write Yes/Y/y. Any other response, or empty response, will be considered as no."
	    read user_answer

	    if echo $user_answer | egrep -iq "^(y|yes)$"
	    then
	        rm -f ${compressed_file_name}
	    fi
	fi
}

createTempDirs()
{
    echo "Creating temp dirs structure to store the data..."
    for new_dir in kerberos_conf pam_conf sssd_conf nsswitch_conf dcvgldiag nvidia_info warnings xorg_log xorg_conf dcv_conf dcv_memory_config dcv_log os_data os_log journal_log hardware_info gdm_log gdm_conf lightdm_log lightdm_conf sddm_log sddm_conf xfce_conf xfce_log systemd_info smart_info network_log ${dcv_report_dir_name} cron_data cron_log
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
    echo "Checking packages versions... depending of your server it can take up to 2 minutes..." | tee -a $dcv_report_path
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
			reportMessage \
			"critical" \
			"Found some DCV packages not compatible." \
			"${target_dir}/dcv_packages_not_os_compatible" \
			"You need to setup the right DCV packages for your Linux distribution." \
			"null" 
	        echo $dcv_packages_not_compatible | tee -a ${target_dir}/dcv_packages_not_os_compatible $dcv_report_path
		else
			reportMessage \
			"info" \
			"DCV packages versions are compatible with current Linux distribution." \
			"null" \
			"null" \
			"null"
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
	                	echo "Warning: $package version $version might be too old for Ubuntu $ubuntu_version. Expected minimum year: $min_year" | tee -a  ${target_dir}/dcv_packages_version_mismatch ${dcv_report_path}
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
    target_dir="${temp_dir}/os_data/"

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
    echo "Collecting all SSSD relevant info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/sssd_conf/"

    if [ -d /etc/sssd/ ]
    then
        sudo cp -r /etc/sssd ${target_dir} > /dev/null 2>&1
    fi

    detect_service=""
    detect_service=$(sudo ps aux | egrep -iv "${NISPGMBHHASH}" | egrep -i '[s]ssd')
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

getXfceData()
{
    echo "Collecting all XFCE relevant info..."
    target_dir="${temp_dir}/xfce_log/"

    sudo journalctl --no-page | egrep -i "[x]fce" >> ${target_dir}/journalctl_xfce_log
}

checkDisplayManager()
{
	if $redhat_distro_based
	then
		display_manager_path="/etc/systemd/system/display-manager.service"
		if [ -f $display_manager_path ]
		then
			display_manager_name=$(basename ${display_manager_path} .service)
		fi
	fi

	if $ubuntu_distro
	then
		display_manager_path="/etc/X11/default-display-manager"
		if [ -f $display_manager_path ]
		then
			display_manager_name=$(basename ${display_manager_pat}h .service)
		fi
	fi

    if command_exists systemctl
	then
        if systemctl is-active --quiet "${display_manager_name}.service"
		then
			reportMessage \
			"info" \
			"${display_manager_name} >> IS RUNNING <<." \
			"null" \
			"null" \
			"null"
			display_manager_status="running"
        else
			reportMessage \
			"critical" \
			"${display_manager_name} >> IS NOT RUNNING <<." \
			"${temp_dir}/warnings/display_manager_${display_manager_name}_is_NOT_running" \
			"You need to check your journalctl to understand why your display-manager is down. You can find more about display managers here:" \
			"https://www.ni-sp.com/knowledge-base/dcv-general/kde-gnome-mate-and-others/"
			display_manager_status="not running"
        fi
    else
        if pgrep -x "${display_manager_name}" >/dev/null
		then
			reportMessage \
			"info" \
			"Status: ${display_manager_name} >> IS RUNNING <<." \
			"null" \
			"null" \
			"null"
			display_manager_status="running"
        else
			reportMessage \
			"critical" \
			"Status: ${display_manager_name} >> IS NOT RUNNING <<." \
			"null" \
			"You need to check your /var/log/messages or /var/log/dmesg to understand why your display-manager is down. You can find more about display managers here:" \
			"https://www.ni-sp.com/knowledge-base/dcv-general/kde-gnome-mate-and-others/"
			display_manager_status="not running"
        fi
    fi
}

lookForDmIssues()
{
	log_dir_to_look=$1
	warning_dir=$2
	
	regular_expression="(fail|cannot|unable|crash|segfault|timeout|fatal|error|denied|segmentation|abort|too many)"
	if egrep -Ri "$regular_expression" $log_dir_to_look > ${warning_dir}/${display_manager_name}_errors
	then
		reportMessage \
		"warning" \
		"Found some unusual error/fail/deny/timeout in SDDM logs." \
		"${temp_dir}/warnings/gdm_errors" \
		"Look our tutorial about how to correctly build SDDM environment in:" \
		"https://www.ni-sp.com/knowledge-base/dcv-general/kde-gnome-mate-and-others/"

		if egrep -Ri "$regular_expression" $log_dir_to_look  | egrep -i dcv > ${warning_dir}/${display_manager_name}_dcv_errors
		then
			reportMessage \
			"critical" \
			"Found some DISPLAY MANAGER issue that are causing issues with DCV." \
			"${warning_dir}/${display_manager_name}_dcv_errors" \
			"Please check your >> $display_manager_name << DISPLAY MANAGER logs to understand why DCV process is being affected." \
			"null"
		fi
	else
		reportMessage \
		"info" \
		"No relevant error found in hte log ${log_dir_to_look}." \
		"null" \
		"null" \
		"null"
	fi
}

getGdmData()
{
    echo "Collecting all GDM relevant info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/gdm_log/"

    if [ -f /var/log/gdm ]
    then
        sudo cp -r /var/log/gdm $target_dir > /dev/null 2>&1
    fi

    if [ -f /var/log/gdm3 ]
    then
        sudo cp -r /var/log/gdm3 $target_dir > /dev/null 2>&1
    fi

    sudo journalctl -u gdm.service > "${target_dir}/journal_gdm"

	lookForDmIssues	$target_dir ${temp_dir}/warnings/

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
}

getSddmData()
{
    echo "Collecting all SDDM relevant info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/sddm_conf/"
	sudo cp -r /etc/sddm* $target_dir
	
    target_dir="${temp_dir}/sddm_log/"
	sudo cp -r /var/log/sddm* $target_dir
	sudo journalctl -u sddm.service > ${target_dir}/journal_sddm

	lookForDmIssues	$target_dir ${temp_dir}/warnings/
}

getLightdmData()
{
    echo "Collecting all LIGHTDM relevant info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/lightdm_conf/"
	sudo cp -r /etc/lightdm* $target_dir

    target_dir="${temp_dir}/lightdm_log/"
	sudo cp -r /var/log/lightdm* $target_dir
	sudo journalctl -u lightdm.service > ${target_dir}/journal_sddm

	lookForDmIssues	$target_dir ${temp_dir}/warnings/
}

getHwData()
{
    echo "Collecting all Hardware relevant info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/hardware_info/"

    if command_exists lshw > /dev/null
    then
        sudo lshw > ${target_dir}/lshw_hardware_info.txt
    else
        echo "lshw not found" > ${target_dir}/not_found_lshw
    fi

    if command_exists lscpu
    then
        sudo lscpu  > ${target_dir}/lscpu_hardware_info.txt
    else
        echo "lscpu not found" > ${target_dir}/not_found_lscpu
    fi

    if command_exists dmidecode
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
    echo "If is possible, please write \"yes\". Any other response, or empty response, will be considered as no."
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
            sudo journalctl -n 30000 > ${target_dir}/journal_last_30000_lines.log
            sudo journalctl --no-page | grep -i selinux > ${target_dir}/selinux_log_from_journal
            sudo journalctl --no-page | grep -i apparmor > ${target_dir}/apparmor_log_from_journal
        fi 
    else
        echo "dcv reboot test not executed" > ${target_dir}/dcv_reboot_test_not_executed
    fi
}

getDcvMemoryConfig()
{
    echo "Collecting all DCV relevant data..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/dcv_memory_config/"

	if command_exists dcv
	then
		sudo dcv get-config --all > ${target_dir}/dcv_config_info
		sudo dcv list-sessions > ${target_dir}/dcv_list_sessions
		sudo dcv list-sessions --json > ${target_dir}/dcv_list_sessions_json
	else
        reportMessage \
        "critical" \
        ">> dcv << binary was not found tine the PATH >> $PATH <<." \
        "${temp_dir}/warnings/dcv_binary_not_found" \
        "Please check if DCV server was correctly installed and if is your PATH variable. The script can not execute dcv commands." \
		"null"
	fi
}

getDcvData()
{
    echo "Collecting all DCV relevant data..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/dcv_conf/"

    if [ -d /etc/dcv ]
    then
        echo "Copying the dcv etc files..."
        sudo cp -r /etc/dcv $target_dir > /dev/null 2>&1
    else
        echo -e "${RED}/etc/dcv not found!${NC}" | tee -a $target_dir/etc_dcv_dir_not_found $dcv_report_path
    fi    

    target_dir="${temp_dir}/dcv_log/"
    
    echo "Copying the dcv log directory..."
    if [ -d /var/log/dcv ]
    then
        sudo cp -r /var/log/dcv $target_dir > /dev/null 2>&1
    else
        echo -e "${RED}/var/log/dcv not found!${NC}" | tee -a $target_dir/var_log_dcv_not_found $dcv_report_path
    fi

    echo "Checking for signal 11 events..." | tee -a $dcv_report_path
    if cat ${target_dir}/dcv/*.log.* | egrep -iq "killed by signal 11"
    then
		reportMessage \
		"critical" \
		"Found DCV process being killed with signal 11 (segmentation fault)" \
		"${temp_dir}/warnings/dcv_logs_kill_signal_11_found" \
		"$dcv_report_text_about_segfault" \
		"https://www.ni-sp.com/knowledge-base/dcv-general/common-problems-linux/#h-dcv-segmentation-fault"
	else
		reportMessage \
		"info" \
		"Did not find signal 11 events (segmentation fault) for DCV." \
		"null" \
		"null" \
		"null"
    fi

	if egrep -Riq "(invalid-session-id|unknown session)" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"Found invalid or unknown session id issue." \
		"${temp_dir}/warnings/dcv_invalid_session_id" \
		"You need to check the server.log to identify the root cause of the invalid/unknown session id. The usually causes are (1) License issues (2) Session creatuion timeouts (3) Invalid session id from the client." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find invalid session id messages." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "Communications error with license server" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"Found network issue to DCV Server talk with your license server." \
		"${temp_dir}/warnings/dcv_network_issue_with_license_server" \
		"Please check if (1) your license server service is running and (2) if there is no firewall blocking the communication. The server.log suggests that DCV Server is not able to communicate with your license server." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find issue with license server." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "Could not create.*session" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"Found issue to create a session." \
		"${temp_dir}/warnings/dcv_could_not_create_session" \
		"The session creation is failing. You need to check the root cause in the server.log file. The common causes are (1) License issue (limits, license server offline or not valid license) (2) Session with ID already being used (3) SELINUX blocking the session creation." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find issue to request the session creation." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "Could not acquire dcv licenses" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"DCV Server can not get the license." \
		"${temp_dir}/warnings/dcv_server_can_not_acquire_dcv_licenses" \
		"You need to check the server.log why the license can not be imported. The common causes are (1) License server offline (2) License permission issue (3) License file missing." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find issue with dcv license import." \
		"null" \
		"null" \
		"null"
	fi

    echo "Checking for not authorized channels events..." | tee -a $dcv_report_path
    if egrep -Riq ".*not authorized in any channel.*" ${target_dir}/*
    then
		reportMessage \
		"critical" \

		"Found NOT AUTHORIZED EVENT IN ANY CHANNEL." \
		"${temp_dir}/warnings/possible_owner_session_issue" \
		"There are users that can not enter in a session due not enough permissions." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/authentication/#h-login-not-working-due-not-authorized-in-any-channel"
        cat ${target_dir}/dcv/server* | egrep -i ".*not authorized in any channel.*" | tee -a ${temp_dir}/warnings/possible_owner_session_issue $dcv_report_path
	else
		reportMessage \
		"info" \
		"Did not find not authorized channel events." \
		"null" \
		"null" \
		"null"
    fi
    
    echo "Checking for RLM permission issues..." | tee -a $dcv_report_path
    if cat ${target_dir}/dcv/server* | egrep -iq ".*RLM Initialization.*failed.*permission denied.*13.*"
    then
		reportMessage \
		"critical" \
		"Found RLM PERMISSION ISSUES..." \
		"${temp_dir}/warnings/rlm_failed_permission_denied" \
		"You need to fix the RLM permissions." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/nice-dcv-licensing/#h-installing-the-rlm-license-server"

        echo ">> RLM Initialization failed: permission denied << message found in server.log files" | tee -a ${temp_dir}/warnings/rlm_failed_permission_denied $dcv_report_path
	else
		reportMessage \
		"info" \
		"Did not find RLM permission issues." \
		"null" \
		"null" \
		"null"
    fi

    echo "Checking for client access denied events..." | tee -a $dcv_report_path
    if cat ${target_dir}/dcv/server* | egrep -iq ".*client will not be allowed to connect.*"
    then
		reportMessage \
		"critical" \
		"Found CLIENT WILL NOT BE ALLOWED TO CONNECT." \
		"${temp_dir}/warnings/client_will_not_be_allowed_to_connect" \
		"You need to check your server.log to identify the root cause." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/authentication/#h-login-not-working-due-not-authorized-in-any-channel"
	else
		reportMessage \
		"info" \
		"Did not find client access denied events." \
		"null" \
		"null" \
		"null"
    fi

    echo "Checking for too many files warnings..." | tee -a $dcv_report_path
    if egrep -iq ".*too many files open.*" ${target_dir}/dcv/server*
    then
		reportMessage \
		"critical" \
		"Found too many files open error." \
		"${temp_dir}/warnings/too_many_open_files_error" \
		"You need to check if DCV reached your Linux security limits or if you are having some filesystem issue that is blocking DCV service to close the file descriptors. Please check your server.log* files." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find too many files open error messages." \
		"null" \
		"null" \
		"null"
    fi

    echo "Checking if QUIC is being started..."
    if cat ${target_dir}/dcv/server.log | egrep -iq "QUIC frontend enabled"
    then
        temp_quic_enabled=true
    fi

    echo "Checking for license and network related events..." | tee -a $dcv_report_path
    if egrep -iq "bad.*hostname.*license" ${target_dir}/dcv/server* 
    then
		reportMessage \
		"critical" \
		"Found BAD HOSTNAME LICENSE." \
		"${temp_dir}/warnings/bad_server_hostname_in_license_issue" \
		"Check your server.log file" \
		"null"
	else
		reportMessage \
		"info" \
		"Your hostname license is correct." \
		"null" \
		"null" \
		"null"
    fi

	echo "Checking relevant info about QUIC..." | tee -a $dcv_report_path
    if ! cat ${target_dir}/dcv/server* | egrep -iq "quictransport"
    then
        if $temp_quic_enabled
        then
            echo -e "${YELLOW}QUIC is ENABLED, but >> quictransport << was never mentioned in server.log files.${NC}" | tee -a ${temp_dir}/warnings/quic_enabled_and_seems_never_used $dcv_report_path
        else
            echo -e "${YELLOW}QUIC is DISABLED and >> quictransport << was never mentioned in server.log files.${NC}" | tee -a ${temp_dir}/warnings/quic_disabled_and_seems_never_used $dcv_report_path
        fi
    fi

    echo "Checking for old DCV Viewer versions..." | tee -a $dcv_report_path
    if egrep -iq "DCV Viewer.*202[23]" ${target_dir}/dcv/agent*
    then
		reportMessage \
		"warning" \
		"Found DCV Viewer 2022 or 2023 versions." \
		"${temp_dir}/warnings/found_dcv_viewer_2022_2023" \
		"We recommend to use DCV Viewer 2024 version, even if your server is not using the 2024 version." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find too old DCV Viewer clients connecting." \
		"null" \
		"null" \
		"null"
    fi

	echo "Checking for DCV license issues..." | tee -a $dcv_report_path
    if [ -f /var/log/dcv/server.log ]
    then
        if egrep -iq "No license for product" /var/log/dcv/server.log
        then
			reportMessage \
			"critical" \
			"No license for product found." \
			"${temp_dir}/warnings/dcv_not_found_valid_license" \
			"You need to set correctly your license to allow DCV resources." \
			"https://www.ni-sp.com/knowledge-base/dcv-general/nice-dcv-licensing/"
		else
			reportMessage \
			"info" \
			"License is configured." \
			"null" \
			"null" \
			"null"
        fi
    fi

	echo "Checking /etc/dcv/dcv.conf file..." | tee -a $dcv_report_path

    if sudo dcv get-config --all | egrep -i "no-tls-strict" | egrep -iq "false"
    then
		reportMessage \
		"warning" \
		"no-tls-strict is false!" \
		"${temp_dir}/warnings/dcv_server_no-tls-strict_is_false" \
		"If your certificate expire, you can ignore and avoid issues. Expired certificate does not mean that you have a security issue. You can set no-tls-strict=true under [security] section of dcv.conf file." \
		"null"
    fi

	if sudo dcv get-config --all | egrep -i "enable-quic-frontend" | egrep -iq "false"
	then
		reportMessage \
		"critical" \
		"QUIC/UDP protocol is not enabled!" \
		"${temp_dir}/warnings/dcv_server_quic_not_enabled" \
		"QUIC/UDP can provide a much better experience if you have high latency and frequent packetloss. You can enable the QUIC/UDP protocol under [connectivity] section of the file dcv.conf with these parameters: enable-quic-frontend=true and enable-datagrams-display = always-off, in different lines." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-how-to-enable-the-udp-based-quic-transport-protocol-in-dcv"
	else
		reportMessage \
		"info" \
		"QUIC/UDP is being listened." \
		"null" \
		"null" \
		"null"
    fi

	if egrep -Riq "Failed checkout of product.*with version" ${target_dir}/* > /dev/null 2>&1
	then
        reportMessage \
        "critical" \
        "You have a license issue. Your current license is expired or does not support your current DCV version." \
        "${temp_dir}/warnings/dcv_license_version_failure" \
        "Please contact the NISP support to check how this can be solved." \
		"https://www.ni-sp.com/support/"		
		
		egrep -Ri "Failed checkout of product.*with version" ${target_dir}/* >> ${temp_dir}/warnings/dcv_license_version_failure
	else
		reportMessage \
		"info" \
		"Your license supports your DCV Server version." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "There was a problem stopping the session" ${target_dir}/* > /dev/null 2>&1
	then
        reportMessage \
        "critical" \
        "Your DCV server can not close some sessions." \
        "${temp_dir}/warnings/dcv_server_can_not_close_session" \
        "Please contact the NISP support to check how this can be solved:" \
		"https://www.ni-sp.com/support/"		

		egrep -Ri "There was a problem stopping the session" ${target_dir}/* > ${temp_dir}/warnings/dcv_server_can_not_close_session
	else
		reportMessage \
		"info" \
		"Did not find issues stopping the sessions." \
		"null" \
		"null" \
		"null"
	fi

	log_files=$(find -iname "agent.*.log*" 2>/dev/null)
	for log_file in $log_files
	do
	    drop_rate_count=$(grep -c "drop_rate" "$log_file" 2>/dev/null)
    
		count_drop_rate_cases=0
    	if [ "$drop_rate_count" -gt 80 ]
		then
			count_drop_rate_cases=$((count_drop_rate_cases + 1))
			user_drop_rate=$(echo $log_file | cut -d"." -f3)
        	reportMessage \
			"warning" \
			"Found >> $drop_rate_count << drop_rate messages from the user >> $user_drop_rate <<." \
			"${temp_dir}/warnings/drop_rate_messages_${user_drop_rate}" \
			"The drop_rates messages are about DCV trying to keep high image quality, high frame rate and best responsiveness without use too much bandwidth, but if the encoder process is slow or your link is oscilating too much the performance or has limited bandwidth capacity, you will see a lot of drop_rate messages. Is normal to see them in the log, but if they persist for long periods or are being printed with some frequency, then you need to investigate your server and network performance." \
			"https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-drop-rate-messages https://www.ni-sp.com/knowledge-base/dcv-general/tips-and-tricks-linux/#h-testing-your-network-bandwidth-and-packet-losses https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-dcv-high-bandwidth-usage-and-stuttering"
    	fi
	done

	if [ $count_drop_rate_cases -eq 0 ]
	then
		reportMessage \
		"info" \
		"Did not find relevant drop rate cases." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "No frame ack from the client.*, video streaming is blocked for channel" ${target_dir}/*
	then
		reportMessage \
		"warning" \
		"Video streaming was blocked due no frame ack from the client." \
		"${temp_dir}/warnings/no_frame_ack_from_the_client_video_streaming_blocked" \
		"This happens when you are having issues with saturated encoding process or network resources limitations. You need to check if users are having DCV black screen or stuttering." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-drop-rate-messages https://www.ni-sp.com/knowledge-base/dcv-general/tips-and-tricks-linux/#h-testing-your-network-bandwidth-and-packet-losses https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-dcv-high-bandwidth-usage-and-stuttering"
	else
		reportMessage \
		"info" \
		"No frame ack issues found." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "No protocol specified" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"Found permission issue when DCV tried to access X server." \
		"${temp_dir}/warnings/dcv_without_x_grant_permission" \
		"If DCV can not access the X server service, it can not share the session with the DCV client. You need to identify what is wrong with your X environment that is not making possivle to dcvxgrantaccess, a xhost wrapper, to add DCV permissions. If you removed some DCV files from your display manager, or customized in a wrong way, you probably need to reinstall DCV server to get the additional code again." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/sessions/#h-could-not-create-a-session-due-no-protocol-specified" \
	else
		reportMessage \
		"info" \
		"No issues with X and DCV agent permissions." \
		"null" \
		"null" \
		"null"
	fi
}

runDcvgldiag()
{
    target_dir="${temp_dir}/dcvgldiag/"

    if command_exists dcvgldiag
    then
		echo "" >> $dcv_report_path
		echo "Executing dcvgldiag test..." | tee -a $dcv_report_path

		if command_exists dcvgldiag
		then
	        sudo dcvgldiag -l ${target_dir}/dcvgldiag.log > /dev/null 2>&1
		fi

		if [ -f ${target_dir}/dcvgldiag.log ]
		then
			if cat ${target_dir}/dcvgldiag.log | egrep -iq "test result.*error"
			then
				cat ${target_dir}/dcvgldiag.log | tee -a $dcv_report_path > /dev/null
				sed -i 's/Test Result: ERROR/[0;31mTest Result: ERROR[0m/g' $dcv_report_path
				sed -i 's/Test Result: SUCCESS/[0;32mTest Result: SUCCESS[0m/g' $dcv_report_path

				reportMessage \
				"warning" \
				"Errors found in DCVGLDIAG test." \
				"null" \
				"Execute the \"dcvgldiag\" command and check the report." \
				"null"
			fi
		fi

        if cat ${target_dir}/dcvgldiag.log | egrep -iq "Test Result: ERROR"
        then
            dcvgldiag_errors_count=$(egrep -ic "Test Result: ERROR" ${target_dir}/dcvgldiag.log)
            echo "found >> $dcvgldiag_errors_count << tests with error result" > ${temp_dir}/warnings/dcvgldiag_found_${dcvgldiag_errors_count}_errors
        fi

        if sudo lsmod | grep -iq "nouveau"
        then
			reportMessage \
			"critical" \
			"Found nouveau driver loaded." \
			"${temp_dir}/warnings/nouveau_kernel_module_found" \
			"You need to block the opensource nouveau driver, otherwise the nvidia module will not be loaded." \
			"https://www.ni-sp.com/knowledge-base/dcv-general/nvidia-cuda/#h-how-to-block-nouveau-driver"
		else
			reportMessage \
			"info" \
			"Did not find nouveau driver loaded." \
			"null" \
			"null" \
			"null"
        fi
    else
		reportMessage \
		"warning" \
		"dcvgldiag not installed" \
		"${temp_dir}/warnings/dcvgldiag_not_installed" \
		"This is a important tool from DCV Team that checks most common Xorg issues that can cause DCV bad performance or problems. You can get the dcvgldiag tool from the DCV Server package." \
		"https://www.ni-sp.com/dcv-download/"
    fi
}

getNvidiaInfo()
{
	echo "Getting nvidia-smi info..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/nvidia_info/"
    if command_exists nvidia-smi
    then
        timeout_seconds=20
        echo "Executing nvidia-smi special query. The test will take up to >> $timeout_seconds << seconds."
        timeout $timeout_seconds nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,pstate,pcie.link.gen.max,pcie.link.gen.current,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.free,memory.used --format=csv -l 5 -f ${target_dir}/nvidia_query > /dev/null 2>&1

        echo "Executing nvidia-smi generic query. The test will take up to >> $timeout_seconds << seconds." | tee -a $dcv_report_path
        timeout $timeout_seconds nvidia-smi 2>&1 | tee -a ${target_dir}/nvidia-smi_command $dcv_report_path
    fi

	if sudo systemctl list-unit-files | grep -q nvidia-persistenced
	then
		if sudo systemctl is-enabled --quiet nvidia-persistenced
		then
			if sudo systemctl is-active --quiet nvidia-persistenced
			then
				reportmessage \
				"info" \
				"nvidia-persistenced is >> RUNNING <<." \
				"null" \
				"null" \
				"null"
			else
				reportmessage \
				"warning" \
				"nvidia-persistenced systemd service is >> NOT RUNNING <<." \
				"${temp_dir}/warnings/nvidia_persistenced_not_running" \
				"Ideally the nvidia-persistenced must be enabled and running, unless if you have special reasons to not have this service enabled." \
				"https://www.ni-sp.com/knowledge-base/dcv-general/nvidia-cuda/#h-nvidia-persistenced-is-not-running"
			fi
		fi
		
		sudo journalctl -u nvidia-persistenced  >> ${target_dir}/nvidia_persistenced_log
	fi
}

getSystemdData()
{
    echo "Collecting all SystemD relevant data..."
    target_dir="${temp_dir}/systemd_info/"
    sudo cp -a /etc/systemd/system/dcv*  ${target_dir}

}

getOsData()
{
    echo "Collecting all Operating System relevant data..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/os_data/"
    sudo uname -a > $target_dir/uname_-a

	if command_exists lsmod
	then
		sudo lsmod >> $target_dir/lsmod
	fi

    if command_exists lsb_release
    then
        sudo lsb_release -a > $target_dir/lsb_release_-a 2>&1
    else
        echo "lsb_release not found" > $target_dir/not_found_lsb_release
    fi

    if command_exists getenforce
    then
        sudo getenforce > $target_dir/getenforce_result 2>&1
        if cat $target_dir/getenforce_result | egrep -iq "enforcing"
        then
            echo -e "${YELLOW}SELINUX is being enforced!${NC}" | tee -a ${temp_dir}/warnings/selinux_is_enforced $dcv_report_path > /dev/null
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

    if command_exists dpkg
    then
        sudo dpkg -a > ${target_dir}/deb_packages_list 2>&1
    fi

    if command_exists rpm
    then
        sudo rpm -qa > ${target_dir}/rpm_packages_list 2>&1
    fi

    if command_exists uptime
	then
    	uptime > ${target_dir}/uptime 2>&1
	fi

    if [ -d /etc/modules-load.d/ ]
    then
        sudo cp -R /etc/modules* ${target_dir}/
    fi

    if [ -d /etc/modprobe.d/ ]
    then
        sudo cp -R /etc/modprobe* ${target_dir}/
    fi

    ps aux --forest > ${target_dir}/ps_aux_--forest 2>&1
    pstree -p > ${target_dir}/pstree 2>&1

    echo "Copying some /var/log/ relevant files..."
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

    if [ -f ${target_dir}/deb_packages_list ]
    then
        pkg_names="(vnc|tiger[^a-z]|team[vV]iewer|any(desk|where)|nomachine|teradici|xrdp|x2go|remmina|spice|guacamole|krdc|rustdesk|dwservice|wayk|meshcentral|remotely|thinlinc|parsec|moonlight|sunshine|webtop|chrome-remote|remotepc|splashtop|logmein|screen-connect|connectwise)"
        if cat ${target_dir}/deb_packages_list | egrep -iq "${pkg_names}"
        then
            cat ${target_dir}/deb_packages_list | egrep -iq "${pkg_names}" > ${temp_dir}/warnings/remote_desktop_server_found
        fi
    fi

    if [ -f ${target_dir}/rpm_packages_list ]
    then
        pkg_names="(vnc|tiger[^a-z]|team[vV]iewer|any(desk|where)|nomachine|teradici|xrdp|x2go|remmina|spice|guacamole|krdc|rustdesk|dwservice|wayk|meshcentral|remotely|thinlinc|parsec|moonlight|sunshine|webtop|chrome-remote|remotepc|splashtop|logmein|screen-connect|connectwise)"
        if cat ${target_dir}/rpm_packages_list | egrep -iq "${pkg_names}"
        then
            cat ${target_dir}/rpm_packages_list | egrep -iq "${pkg_names}" > ${temp_dir}/warnings/remote_desktop_server_found
        fi
    fi

    if [ -f $target_dir/dmesg ]
    then
        if cat $target_dir/dmesg | egrep -i "oom" > /dev/null 2>&1
        then
			echo -e "${YELLOW}Possible OOM Killer events found... please check your /var/log/dmesg files${NC}" | tee -a $dcv_report_path
            cat $target_dir/dmesg | egrep -i "(oom|killed|killer)" | tee -a ${temp_dir}/warnings/possible_oom_killer_log_found_dmesg > /dev/null
        fi

        if cat $target_dir/dmesg | egrep -iq "(segfault|segmentation fault)" > /dev/null 2>&1
        then
			echo -e "${YELLOW}Segmentation fault events found... please check your /var/log/dmesg files${NC}" | tee -a $dcv_report_path
            cat $target_dir/dmesg | egrep -i "(segfault|segmentation fault)" | tee -a ${temp_dir}/warnings/segmentation_fault_found > /dev/null
        fi
    fi

    if [ -f $target_dir/messages ]
    then
        if cat $target_dir/messages | egrep -iq "oom" > /dev/null 2>&1
        then
			reportMessage \
			"critical" \
			"Possible OOM Killer events found!" \
			"${temp_dir}/warnings/possible_oom_killer_log_found_messages" \
			"You need to check the cause of OOM Killer action and check if it is affecting DCV and related services (X, display manager, session manager etc)." \
			"null"

            cat $target_dir/messages | egrep -i "(oom|killed|killer)" | tee -a ${temp_dir}/warnings/possible_oom_killer_log_found_messages > /dev/null
		else
			reportMessage \
			"info" \
			"Did not find OOM Killer events." \
			"null" \
			"null" \
			"null"
        fi

        echo "Checking for SELinux logs... if you have big log files, please wait for a moment..." | tee -a $dcv_report_path
		
        grep -i "selinux is preventing" $target_dir/messages* | grep -i "dcv" | while read -r line 
        do
            echo "$line" | tee -a ${temp_dir}/warnings/selinux_is_preventing_dcv > /dev/null
        done
		
		if [ -f ${temp_dir}/warnings/selinux_is_preventing_dcv ] 
		then
			reportMessage \
			"critical" \
			"Found SELINUX preventing DCV service to work." \
			"${temp_dir}/warnings/selinux_is_preventing_dcv" \
			"Please review your /var/log/messages to identify which DCV service is being blocked by SELINUX." \
			"null"
		else
			reportMessage \
			"info" \
			"Did not find SELINUX preventing DCV service to work." \
			"null" \
			"null" \
			"null"
		fi
    fi

    target_dir="${temp_dir}/journal_log"
    echo "Collecting journalctl data... if you have a long history stored, please wait for a moment." | tee -a $dcv_report_path

    echo "Reading journalctl log..."
    sudo journalctl -n 30000 > ${target_dir}/journal_last_30000_lines.log 2>&1

    echo "Reading possible selinux log..."
    sudo journalctl --no-page | grep -i selinux > ${target_dir}/selinux_log_from_journal 2>&1

    echo "Reading possible apparmor log..."
    sudo journalctl --no-page | grep -i apparmor > ${target_dir}/apparmor_log_from_journal 2>&1

	echo "Looking for OOM killer fault events"

    echo "Looking for segmentation fault events..."
    if egrep -Riq "(segfault|segmentation fault)" ${target_dir}/* > /dev/null 2>&1
    then
		reportMessage \
		"warning" \
		"Segmentation fault events found in journalctl..." \
		"${temp_dir}/warnings/segmentation_fault_found" \
		"${dcv_report_text_about_segfault}" \
		"https://www.ni-sp.com/knowledge-base/dcv-general/common-problems-linux/#h-dcv-segmentation-fault"

		if egrep -Ri "(segfault|segmentation fault)" ${target_dir}/* | egrep -iq "dcv" > /dev/null 2>&1
		then
        	egrep -Ri "(segfault|segmentation fault)" ${target_dir}/* | egrep -i "dcv" tee -a ${temp_dir}/warnings/segmentation_fault_found $dcv_report_path > /dev/null
			reportMessage \
			"critical" \
			"DCV process is having segmentation fault." \
			"${temp_dir}/warnings/segmentation_fault_found_dcv" \
			"${dcv_report_text_about_segfault}" \
			"https://www.ni-sp.com/knowledge-base/dcv-general/common-problems-linux/#h-dcv-segmentation-fault"
		fi

	else
		reportMessage \
		"info" \
		"Did not find segmentation fault events." \
		"null" \
		"null" \
		"null"
    fi

	if egrep -Riq "Could not get tablet information for 'Xdcv eraser'" ${target_dir}/*
	then
		egrep -Ri "Could not get tablet information for 'Xdcv eraser'" ${target_dir}/* >> ${temp_dir}/warnings/Xdcv_errors
		reportMessage \
        "critical" \
        "Identified some issue with Xdcv and gnome-shell." \
        "${temp_dir}/warnings/Xdcv_errors" \
        "Found and issue between gnome-shell and Xdcv. Please check if you are using X11, not Wayland, and if you have a complete GNOME environment installed." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find Xdcv eraser issues events." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "gnome-.*Fatal IO error" ${target_dir}/*
	then
		reportMessage \
        "critical" \
        "Identified Fatal IO error with gnome component." \
        "${temp_dir}/warnings/gnome_fatal_io_error" \
        "There is a chance that you have a corrupted filesystem or volume. You need to check your filesystem and OS integrity to understand why you are getting I/O errors." \
		"null"
		
		egrep -Ri "gnome-terminal-server.*Fatal IO error" >> ${temp_dir}/warnings/gnome_fatal_io_error
	else
		reportMessage \
		"info" \
		"Did not find GNOME IO error events." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "BAR.*failed to assign" ${target_dir}/*
	then
        reportMessage \
        "warning" \
        "Found BAR failures" \
        "${temp_dir}/warnings/bar_failures_found" \
        "BAR stands for Base Address Register, which is a mechanism used by PCI devices to request memory or I/O space from the system. These errors typically occur when: (A) The system doesn't have enough I/O address space available to satisfy all PCI devices. (B) There might be conflicts between devices requesting the same resources. (C) The BIOS/UEFI didn't properly allocate or reserve the necessary resources. If you are using a virtualized environment with a lot of virtual devices, for example, is possible that your VM has not enough resources to support all devices, what can cause DCV issues, specially when GPU is being used. While these errors look concerning, they don't always cause functional problems. Many systems can still operate normally with some BAR allocation failures, as the kernel typically tries to work around these issues. " \
		"null"
		egrep -Ri "BAR.*failed to assign" >> ${temp_dir}/warnings/bar_failures_found

		reportMessage \
		"info" \
		"Did not find Base Address Register (BAR) failure events." \
		"null" \
		"null" \
		"null"
	fi


	if egrep -Riq "NVIDIA.*Failed to bind sideband socket" ${target_dir}/*
	then
        reportMessage \
        "warning" \
        "NVIDIA: Failed to bind sideband socket" \
        "${temp_dir}/warnings/nvidia_fail_to_bind" \
        "The sideband socket is part of NVIDIA's driver communication system, used for exchanging information between different components of the graphics system. When this binding fails, it typically indicates: (A) A permission problem (the process doesn't have rights to access the socket). (B) The socket is already in use by another process. (C) The NVIDIA driver might be experiencing conflicts with other system components. You need to check if you have conflicting drivers." \
		"null"

		egrep -Ri "NVIDIA.*Failed to bind sideband socket" >> ${temp_dir}/warnings/nvidia_fail_to_bind
	else
		reportMessage \
		"info" \
		"Did not find bind sideband socket failures related with NVIDIA driver." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "Valid GRID license not found" ${temp_dir}/*
	then
		reportMessage \
		"critical" \
		"Valid GRID license not found" \
		"${temp_dir}/warnings/nvidia_grid_license_not_found" \
		"Your GPU card resources is being limited due no license installed. Please install the license to release all GPU resources." \
		"https://www.ni-sp.com/knowledge-base/dcv-general/performance-guide/#h-nvidia-limited-sessions-performance-after-some-sessions-created https://www.ni-sp.com/knowledge-base/dcv-general/nvidia-cuda/#h-valid-grid-license-not-found https://docs.nvidia.com/vgpu/15.0/grid-licensing-user-guide/index.html#configuring-nls-licensed-client"
	else
		reportMessage \
		"info" \
		"No NVIDIA grid license issue found." \
		"null" \
		"null" \
		"null"
	fi
}

getSmartInfo()
{
    if ! command_exists smartctl
    then
        return 1
    else
        echo "Checking S.M.A.R.T...." | tee -a $dcv_report_path
    fi

    target_dir="${temp_dir}/smart_info"
    smart_disk_report="${target_dir}/smart_disk_report_$(date +%Y%m%d).txt"
    smart_disk_warnings="${temp_dir}/warnings/smart_disk_warnings_$(date +%Y%m%d).txt"
    local_storage_devices=$(lsblk -dpno NAME 2>/dev/null | grep -v -E "loop|ram|rom")
    
    if [ -z "$local_storage_devices" ]
    then
        echo "lsblk failed or returned no disks, trying alternative method..." | tee -a $smart_disk_report $dcv_report_path
        local_storage_devices=$(find /dev -regex "/dev/[hsv]d[a-z]" -o -regex "/dev/nvme[0-9]n[0-9]" 2>/dev/null)
    
        if [ -z "$local_storage_devices" ]
        then
            echo "Alternative method failed, trying /proc/partitions" | tee -a $smart_disk_report $dcv_report_path
            local_storage_devices=$(awk '{print $4}' /proc/partitions 2>/dev/null | grep -E "^[hsv]d[a-z]$|^nvme[0-9]n[0-9]$" | sed 's/^/\/dev\//')
        fi
    fi

    for local_storage_device in $local_storage_devices
    do
        if [ ! -b "$local_storage_device" ]
        then
            echo "$local_storage_device is not a valid block device, skipping" | tee -a $smart_disk_report $dcv_report_path
            echo "" | tee -a $smart_disk_report $dcv_report_path
            continue
        fi

        # Check if disk supports SMART with a timeout to prevent hangs on problematic devices
        if ! timeout 10 smartctl -i "$local_storage_device" 2>/dev/null | grep -q "SMART support is: Enabled"
        then
            echo "S.M.A.R.T. not available or not enabled on $local_storage_device" | tee -a $smart_disk_report $dcv_report_path
            continue
        fi

        # Get basic information with timeout
        echo "--- Basic Information ---" | tee -a $smart_disk_report $dcv_report_path
        timeout 5 smartctl -i "$local_storage_device" 2>&1 | tee -a $smart_disk_report $dcv_report_path
    
        # Get health status with timeout
        echo "--- Health Status ---" >> "$smart_disk_report"
        timeout 5 smartctl -H "$local_storage_device" 2>&1 | tee -a $smart_disk_report $dcv_report_path
    
        # Get SMART attributes with timeout
        echo "--- SMART Attributes ---" >> "$smart_disk_report"
        timeout 5 smartctl -A "$local_storage_device" 2>&1 | tee -a $smart_disk_report $dcv_report_path
    
        # Get error logs with timeout
        echo "--- Error Log ---" >> "$smart_disk_report"
        timeout 5 smartctl -l error "$local_storage_device" 2>&1 | tee -a $smart_disk_report $dcv_report_path
    
        # Get self-test logs with timeout
        echo "--- Self-Test Log ---" >> "$smart_disk_report"
        timeout 5 smartctl -l selftest "$local_storage_device" 2>&1 | tee -a $smart_disk_report $dcv_report_path
    
        # Check for warnings
        check_warnings "$local_storage_device"
    done
}

getSmartWarnings()
{
    echo "Checking S.M.A.R.T. warnings..." | tee -a $dcv_report_path
    local disk="$1"
    local disk_name=$(basename "$disk")
    
    # Check overall health
    health=$(smartctl -H "$disk" 2>/dev/null)
    if echo "$health" | grep -q "FAILED"
    then
		reportMessage \
		"warning" \
		"$disk_name - SMART overall health test FAILED!" \
		"$smart_disk_warnings" \
		"Enable the S.M.A.R.T. in your storage devices." \
		"null"
	else
		reportMessage \
		"info" \
		"SMART overall health check as completed with success with the storage device >> $disk_name <<." \
		"null" \
		"null" \
		"null"
    fi
    
    # Check for reallocated sectors
    realloc=$(smartctl -A "$disk" 2>/dev/null | grep "Reallocated_Sector_Ct")
    if [[ -n "$realloc" ]]
    then
        value=$(echo "$realloc" | awk '{print $10}')
        if [[ "$value" -gt 0 ]]
        then
			reportMessage \
			"critical" \
			"$disk_name - Reallocated sectors found: $value" \
			"$smart_disk_warnings" \
			"This indicates that your drive has detected bad sectors and has remapped them to spare sectors. This is an early warning sign of potential drive failure. Please check your drive." \
			"null"
		else
			reportMessage \
			"info" \
			"Did not find reallocated sectors with the storage device >> $disk_name <<." \
			"null" \
			"null" \
			"null"
        fi
    fi
    
    # Check for pending sectors
    pending=$(smartctl -A "$disk" 2>/dev/null | grep "Current_Pending_Sector")
    if [[ -n "$pending" ]]
    then
        value=$(echo "$pending" | awk '{print $10}')
        if [[ "$value" -gt 0 ]]
        then
			reportMessage \
			"critical" \
			"$disk_name - Pending sectors found: $value" \
			"$smart_disk_warnings" \
			"Pending sectors are sectors that have been identified as problematic but haven't yet been remapped. You need to check if you need to replace your storage." \
			"null"
		else
			reportMessage \
			"info" \
			"Did not find pending sectors with the storage device >> $disk_name <<." \
			"null" \
			"null" \
			"null"
        fi
    fi
    
    # Check for offline uncorrectable sectors
    uncorrect=$(smartctl -A "$disk" 2>/dev/null | grep "Offline_Uncorrectable")
    if [[ -n "$uncorrect" ]]
    then
        value=$(echo "$uncorrect" | awk '{print $10}')
        if [[ "$value" -gt 0 ]]
        then
			reportMessage \
			"critical" \
			"$disk_name - Offline uncorrectable sectors found: $value" \
			"$smart_disk_warnings" \
			"These are sectors that the drive has determined are damaged and cannot be read or repaired. You need to replace your storage, as everything can be corrupted." \
			"null"
		else
			reportMessage \
			"info" \
			"Did not find damaged sectors with the storage device >> $disk_name <<." \
			"" \
			"" \
			""
        fi
    fi
    
    # Check temperature (if available)
    temp=$(smartctl -A "$disk" 2>/dev/null | grep -E "Temperature_Celsius|Airflow_Temperature_Cel")
    if [[ -n "$temp" ]]
    then
        temp_value=$(echo "$temp" | head -1 | awk '{print $10}')
        if [[ "$temp_value" -gt 55 ]]
        then
			reportMessage \
			"warning" \
			"$disk_name - High temperature detected: ${temp_value}°C" \
			"$smart_disk_warnings" \
			"High temperatures can damage your storage and corrupt the filesystem. You need to cool down your storage." \
			"null"
		else
			reportMessage \
			"info" \
			"Did not find high temperature with the storage device >> $disk_name <<." \
			"null" \
			"null" \
			"null"
        fi
    fi
    
    # Check for errors in error log
    error_count=$(smartctl -l error "$disk" 2>/dev/null | grep -c "Error")
    if [[ "$error_count" -gt 0 ]]
    then
		reportMessage \
		"critical" \
		"$disk_name - SMART Error Log has $error_count entries" \
		"$smart_disk_warnings" \
		"You need to run >> smartctl -l error << and check all entries. There is a chance that your storage hardware is about to fail." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find errors in smartctl check with the storage device >> $disk_name <<." \
		"null" \
		"null" \
		"null"
    fi
    
    # Check power-on hours (just information, not a warning)
    hours=$(smartctl -A "$disk" 2>/dev/null | grep "Power_On_Hours")
    if [[ -n "$hours" ]];
    then
        hours_value=$(echo "$hours" | awk '{print $10}')
        if [[ "$hours_value" -gt 43800 ]]
        then
            # More than 5 years (24*365*5)
			reportMessage \
			"warning" \
			"$disk_name - Drive has been running for more than 5 years ($hours_value hours)" \
			"$smart_disk_warnings" \
			"Please check your drive health as it is running for more than 5 years. Some devices types, like SSD, will start to have seriously degradation after so much time." \
			"null"
        fi
    fi
}

getXorgData()
{
    echo "Collecting all Xorg relevant data..." | tee -a $dcv_report_path
    target_dir="${temp_dir}/xorg_log/"
    sudo cp -r /var/log/Xorg* $target_dir > /dev/null 2>&1
    
    target_dir="${temp_dir}/xorg_conf/"

    if [[ "${DISPLAY}x" == "x" ]]
    then
		reportMessage \
		"warning" \
		"DISPLAY var content: >> $DISPLAY <<" \
		"${target_dir}/display_content_var ${temp_dir}/warnings/display_var_is_empty" \
		"The DISPLAY var is empty. Is normal if you executed this script outside of GUI session." \
		"null"
        echo "The user executing is >> $USER <<" >> ${temp_dir}/warnings/display_var_is_empty 2>&1
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

		reportMessage \
		"warning" \
		"/usr/share/X11 was found." \
		"${temp_dir}/warnings/usr_share_X11_exist__usually_expected_etc_x11" \
		"You need to check xorg.conf.d of both directories (/etc/X11 and /usr/share/X11) and look for configuration files that can enter in conflict with yout environment. For example: radeon drivers being loaded with nvidia driver. We recommend to backup and remove all xorg.conf.d/* files and leave just the ones that you really need. Also, check your /var/log/Xorg.log* files to verify which directories are being loaded and which xorg.conf file is being used. Sometimes both xorg.conf.d are being loaded, causing issues to your X server." \
		"null"
    fi

    if ls /etc/X11/xorg.conf.d/*nvidia* &>/dev/null
    then
		reportMessage \
		"warning" \
		"A nvidia config file was found in >> /etc/X11/xorg.conf.d/*nvidia* <<. It can cause issues in xorg.conf config file." \
		"${temp_dir}/warnings/nvidia_xorgconf_possible_override" \
		"Check if you really need the additional nvidia configuration files found in /etc/X11/xorg.conf.d/*nvidia*. Usually is better to leave just your xorg.conf file." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find NVIDIA files under /etc/X11/xorg.conf.d/" \
		"null" \
		"null" \
		"null"
    fi

    if ls /usr/share/X11/xorg.conf.d/*nvidia* &>/dev/null
    then
		reportMessage \
		"warning" \
		"A nvidia config file was found in >> /usr/share/X11/xorg.conf.d/*nvidia* <<. It can cause issues in xorg.conf config file." \
		"${temp_dir}/warnings/nvidia_xorgconf_possible_override" \
		"Check if you really need the additional nvidia configuration files found in /usr/share/X11/xorg.conf.d/*nvidia*. Usually is better to leave just your xorg.conf file." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find NVIDIA files under /usr/share/X11/xorg.conf.d/" \
		"null" \
		"null" \
		"null"
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

    if command_exists X
    then
        if pgrep X > /dev/null
        then
            echo "X is currently running. Cannot execute X -configure." | tee -a ${temp_dir}/warnings/X_--configure_failed $dcv_report_path
        else
            timeout_seconds=10
            echo "Executing X -configure query. The test will take up to >> $timeout_seconds << seconds" | tee -a $dcv_report_path
			sudo timeout $timeout_seconds X -configure 2> >(tee -a "${target_dir}/xorg.conf.configure.stderr" $dcv_report_path > /dev/null) | tee -a "${target_dir}/xorg.conf.configure.stdout $dcv_report_path" > /dev/null
        fi
    else
		reportMessage \
		"critical" \
		"X not found, X -configure can not be executed." \
		"${temp_dir}/warnings/X_was_not_found" \
		"X was not found. Maybe your PATH is wrong or you do not have a complete GUI installed. Please check our GUI guide:" \
		"https://www.ni-sp.com/knowledge-base/dcv-general/kde-gnome-mate-and-others/"
    fi

    detect_service=""
    detect_service=$(sudo ps aux | egrep -i '[w]ayland' | egrep -v "tar.gz" | egrep -iv "${NISPGMBHHASH}")
    if [[ "${detect_service}x" != "x" ]]
    then
		reportMessage \
		"critical" \
		"Wayland >> IS << RUNNING!" \
		"${temp_dir}/warnings/wayland_is_running" \
		"You need to run DCV Server with X11 backend. Wayland is not supported yet and will cause issues under DCV Service. The DCV Viewer supports Wayland since 2024.0-17979 version." \
		"null"
	else
		reportMessage \
		"info" \
		"Wayland >> IS NOT << RUNNING!" \
		"${temp_dir}/warnings/wayland_is_not_running" \
		"Wayland is already supported for DCV Viewer, but not DCV Server. The support is under the roadmap and you can check any news here:" \
		"https://docs.aws.amazon.com/dcv/latest/adminguide/doc-history-release-notes.html"
    fi

    XAUTH=$(sudo ps aux | grep "/usr/bin/X.*\-auth" | grep -v grep | sed -n 's/.*-auth \([^ ]\+\).*/\1/p')
    x_display=$(sudo ps aux | egrep '([X]|[X]org|[X]wayland)' | awk '{for (i=1; i<=NF; i++) if ($i ~ /^:[0-9]+$/) print $i}')
    if [[ "${x_display}x" == "x" ]]
    then
		reportMessage \
		"warning" \
		"Not possible to execute xrandr: display not found." \
		"${target_dir}/xrandr_can_not_be_executed" \
		"The DISPLAY variable seems empty. This is normal if you are executing this script outside of GUI session. What you can do is try to export the DISPLAY variable, so the xrandr test will work." \
		"null"
    else
        if command_exists xrandr
        then
            DISPLAY=${x_display} xrandr > ${target_dir}/xrandr_stdout 2> ${target_dir}/xrandr_stderr
        fi

        if command_exists glxinfo
        then
			echo "Checking GLX INFO..." | tee -a $dcv_report_path
            if [ -n "$XAUTH" ]
            then
				sudo -E DISPLAY=${x_display} XAUTHORITY="$XAUTH" glxinfo 2> >(tee "${target_dir}/opengl_errors" $dcv_report_path) | grep -i "opengl.*version" | tee "${target_dir}/opengl_version" $dcv_report_path
            else
				sudo -E DISPLAY=${x_display} glxinfo 2> >(tee "${target_dir}/opengl_errors" $dcv_report_path) | grep -i "opengl.*version" | tee "${target_dir}/opengl_version" $dcv_report_path
            fi
        fi
    fi

	if egrep -Riq "Permission denied" ${target_dir}/*
	then
		reportMessage \
		"critical" \
		"Found permission denied errors in Xorg log." \
		"${temp_dir}/warnings/xorg_permission_denied" \
		"Please check the permissions errors found in your Xorg logs. If you are having permission video driver issues you probably will get performance problems or graphical issues with GNOME and Xorg." \
		"null"

		egrep -Riq "Permission denied" ${target_dir}/* >> ${temp_dir}/warnings/xorg_permission_denied
	else
		reportMessage \
		"info" \
		"Did not find permission denied errors in Xorg log." \
		"null" \
		"null" \
		"null"
	fi

	if egrep -Riq "Unable to get display device" ${target_dir}/*
	then
		reportMessage \
		"warning" \
		"Graphics driver couldn't detect or communicate with a display device." \
		"${temp_dir}/warnings/gpu_driver_unable_get_display_device" \
		"You need to investigate why your GPU driver can not get the Display device data. (1) Usually if you are using the Xorg option UseDisplayDevice set as None, or (2) the server has physical connection issues, you will get this issue. (3) Permissions drivers problems can also cause the issue." \
		"null"
		egrep -Riq "Unable to get display device" >> ${temp_dir}/warnings/gpu_driver_unable_get_display_device
	else
		reportMessage \
		"info" \
		"Did not find issues to get display device info data." \
		"null" \
		"null" \
		"null"
	fi
}

checkDcvManagementLinux()
{
	echo "Checking if DCV Management Linux is present..." | tee -a $dcv_report_path
	if sudo systemctl list-unit-files --type=service | grep -qi "dcv-management"
	then
		if sudo systemctl is-enabled dcv-management &> /dev/null
		then
			dcv_managament_text1="enabled"
			if sudo systemctl is-active &> /dev/null
			then
				dcv_managament_text2="active"
			else
				dcv_managament_text2="not_active"
			fi
		else
			dcv_managament_text1="disabled"
		fi

		reportMessage \
      	"info" \
       	"DCV Management Linux service is >> $dcv_managament_text1 << and >> $dcv_managament_text2 <<." \
        "${temp_dir}/warnings/dcv_management_linux_${dcv_managament_text1}_and_${dcv_managament_text2}" \
        "null" \
		"null"
	fi
}

getCronInfo()
{
	echo "Getting cronjob info..." | tee -a $dcv_report_path
	target_dir="${temp_dir}/cron_logs/"
	
	if [ -f /var/log/cron ]
	then
		sudo cp -a /var/log/cron* $target_dir
	fi

	if [ -f /var/log/crond ]
	then
		sudo cp -a /var/log/cron* $target_dir
	fi
	
	sudo journalctl -u cron.service > ${target_dir}/journal_cron
	sudo journalctl -u crond.service > ${target_dir}/journal_crond
}

getCronData()
{
	echo "Getting cronjob info..." | tee -a $dcv_report_path
	target_dir="${temp_dir}/cron_data/"

	if [ -d /var/spool/cron ]
	then
		sudo cp -a /var/spool/cron/* $target_dir
	fi

    if egrep -Riq "dcv" ${target_dir}/* > /dev/null 2>&1
    then    
        reportMessage \
        "warning" \
		"Found dcv string in cronjobs directory." \
        "${temp_dir}/warnings/dcv_cronjob_match" \
		"Found cronjobs that has the string dcv in the commands. Please be sure that this is not causing any issue to DCV services." \
		"null"
	else
		reportMessage \
		"info" \
		"Did not find dcv string in cronjobs directories." \
		"null" \
		"null" \
		"null"
	fi
}

checkNetwork()
{
	echo "Checking Network services..." | tee -a $dcv_report_path
	target_dir="${temp_dir}/network_log/"

    if command_exists dmesg 
	then
        DMESG_ERRORS=$(sudo dmesg | grep -iE '(eth|eno|ens|enp|wl)[0-9]: (link|driver|hardware|error|timeout)')

        if [ -n "$DMESG_ERRORS" ]
		then
			reportMessage \
			"warning" \
			"Network errors were found in dmesg." \
			"${temp_dir}/warnings/found_network_issues" \
			"You need to troubleshoot what is wrong with your ethernet card or the network, because this can cause issues in the DCV traffic." \
			"null"

            sudo dmesg | grep -iE '(eth|eno|ens|enp|wl)[0-9]: (link|driver|hardware|error|timeout)' | grep -i "error\|fail\|down\|collision\|duplex\|timeout" > ${target_dir}/network_issues_log
		else
			reportMessage \
			"info" \
			"Did not find network errors in the ethernet devices." \
			"null" \
			"null" \
			"null"
        fi
    fi

    if command_exists host || command_exists dig || command_exists nslookup
	then
        if command_exists host
		then
            if ! host $dns_test_domain &>/dev/null
			then
                dns_is_working="false"
            else
                dns_is_working="true"
            fi
        elif command_exists dig
		then
            if ! dig +short $dns_test_domain  &>/dev/null
			then
                dns_is_working="false"
            else
                dns_is_working="true"
            fi
        elif command_exists nslookup
		then
            if ! nslookup $dns_test_domain  &>/dev/null
			then
                dns_is_working="false"
            else
                dns_is_working="true"
            fi
        fi
    else
        dns_is_working="false"
    fi

	if $dns_is_working
	then
		reportMessage \
		"info" \
		"DNS resolution >> IS WORKING <<." \
		"${target_dir}/dns_is_working" \
		"DNS is important to validate your DCV license and to reach your RLM server, if you are using one." \
		"null"
	else
		reportMessage \
		"critical" \
		"DNS resolution >> IS NOT WORKING <<." \
		"${target_dir}/dns_is_NOT_working ${temp_dir}/warnings/dns_is_NOT_working" \
		"You need to check your DHCP server and your /etc/resolv.conf to understand why your server can not solve DNS." \
		"null"
	fi
	
    if command_exists ping
	then
        if ! ping -c 1 -W 3 $ip_test_external &>/dev/null
		then
			reportMessage \
			"warning" \
			"No external connectivity to ${ip_test_external}." \
			"${target_dir}/ping_to_${ip_test_external}_is_NOT_working ${temp_dir}/warnings/ping_to_${ip_test_external}_is_NOT_working" \
			"It seems that you have issues to get external connectivity. Can be your firewall blocking or some network issue. You need to check the DCV server logs for possible network issues." \
			"null"
        else
			reportMessage \
			"info" \
			"External connectivity to ${ip_test_external} was tested and is working." \
			"${target_dir}/ping_to_${ip_test_external}_is_working" \
			"null" \
			"null"
        fi
    fi

	if command_exists netstat
	then
		sudo netstat -nlptu | tee ${target_dir}/network_netstat_nlptu > /dev/null
	fi
}
