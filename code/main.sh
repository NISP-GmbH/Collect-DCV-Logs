# global vars
RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

temp_dir="tmp/"
compressed_file_name="dcv_logs_collection.tar.gz"
ubuntu_distro="false"
ubuntu_version=""
ubuntu_major_version=""
ubuntu_minor_version=""
redhat_distro_based="false"
redhat_distro_based_version=""
force_flag="false"

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
    createTempDirs
    checkPackagesVersions
    getOsData
    getEnvironmentVars
    getHwData
    getGdmData
    getKerberosData
    getSssdData
    getNsswitchData
    getPamData
    getXorgData
    getNvidiaInfo
    getDcvData
    getDcvDataAfterReboot
    runDcvgldiag
    compressLogCollection
    askToEncrypt
    removeTempDirs
    exit 0
}

main
