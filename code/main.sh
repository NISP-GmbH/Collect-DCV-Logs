# global vars
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
BOLD='\033[1m'
temp_dir="tmp/"
compressed_file_name="dcv_logs_collection.tar.gz"
encrypted_file_name="${compressed_file_name}.gpg"
identifier_string=""
encrypt_length="32"
encrypt_password=$(openssl rand -base64 48 | tr -dc '\-A-Za-z0-9@#$%^&*()_=+' | tr -d ' ' | head -c "${encrypt_length}")
upload_domain="https://dcv-logs.ni-sp.com"
upload_url="${upload_domain}/upload.php"
notify_url="${upload_domain}/notify.php"
curl_response=""
curl_http_body=""
curl_http_status=""
curl_filename=""
ubuntu_distro="false"
ubuntu_version=""
ubuntu_major_version=""
ubuntu_minor_version=""
redhat_distro_based="false"
redhat_distro_based_version=""
force_flag="false"
report_only="false"
collect_log_only="false"
option_selected="1"
dcv_report_dir_name="dcv_report"
dcv_report_file_name="dcv_report.txt"
dcv_report_path="${temp_dir}/${dcv_report_dir_name}/${dcv_report_file_name}"
dcv_report_separator="------------------------------------------------------------------"
dns_test_domain="google.com"
ip_test_external="8.8.8.8"
dns_is_working="false"
display_manager_name="gdm"
display_manager_status="not running"
local_storage_devices=""
smart_disk_report=""
smart_disk_warnings=""
NISPGMBHHASH="NISPGMBHHASH"

dcv_report_text_about_segfault="You need to check the system logs to understand which processes are getting segmentation fault and the consequences to DCV environment. Segmentation fault is a system protection that means that some process tried to access non allowed memory region. Usually this happen due software bugs, but sometimes is related with non compatible software, like using DCV in Wayland environment or using multiple remote desktop systems at the same time; As they will compete for same resources, they can have erroneous behavior. For more info, please check: https://www.ni-sp.com/knowledge-base/dcv-general/common-problems-linux/#h-dcv-segmentation-fault "
for arg in "$@"
do
	case $arg in
		--force)
        	force_flag=true
		;;
		--report-only)
			report_only=true
		;;
		--collect_log_only)
			collect_log_only=true
		;;
	esac
done

main()
{
    welcomeMessage
    setupUsefulTools
    createTempDirs
    checkPackagesVersions
    getSystemdData
    getOsData
    getEnvironmentVars
    getHwData
    getSmartInfo

	checkDisplayManager
	case $display_manager_name in
		gdm*)
    		getGdmData
		;;
		sddm*)
			getSddmData
		;;
		lightdm*)
			getLightdmData
		;;
	esac

	getXfceData
	
    getKerberosData
    getSssdData
    getNsswitchData
	getCronInfo
	getCronData
	checkNetwork
    getPamData
    getXorgData
    getNvidiaInfo
    getDcvData
	getDcvMemoryConfig
	checkDcvManagementLinux
    #getDcvDataAfterReboot
    runDcvgldiag
    compressLogCollection
    encryptLogCollection
    uploadLogCollection
    removeTempFiles
    byebyeMessage
    exit 0
}

main

# unknown error
exit 255
