# global vars
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
local_storage_devices=""
smart_disk_report=""
smart_disk_warnings=""
NISPGMBHHASH="NISPGMBHHASH"

for arg in "$@"
do
    if [ "$arg" = "--force" ]
    then
        force_flag=true
        break
    fi
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
    getGdmData
    getXfceLog
    getKerberosData
    getSssdData
    getNsswitchData
    getPamData
    getXorgData
    getNvidiaInfo
    getDcvData
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
