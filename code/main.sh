# global vars
temp_dir="tmp/"
compressed_file_name="dcv_logs_collection.tar.gz"
ubuntu_distro="false"
ubuntu_version=""
ubuntu_major_version=""
ubuntu_minor_version=""
redhat_distro_based="false"
redhat_distro_based_version=""

main()
{
    welcomeMessage
    createTempDirs
    checkPackagesVersions
    getOsData
    getEnvironmentVars
    getHwData
    getGdmData
    getXorgData
    getDcvData
    getDcvDataAfterReboot
    compressLogCollection
    askToEncrypt
    removeTempDirs
    exit 0
}

main
