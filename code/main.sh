# global vars
temp_dir="tmp/"
compressed_file_name="dcv_logs_collection.tar.gz"

main()
{
    welcomeMessage
    createTempDirs
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
