#
# This script changes all unneeded options in the CMakeOptions.txt to OFF for a faster building.
#
declare -a disable_options=("BUILD_rawshark" "BUILD_dumpcap" "BUILD_text2pcap" "BUILD_mergecap" "BUILD_reordercap" "BUILD_editcap" "BUILD_capinfos" "BUILD_captype" "BUILD_randpkt" "BUILD_dftest" "BUILD_androiddump" "BUILD_sshdump" "BUILD_ciscodump" "BUILD_randpktdump" "AUTOGEN_dcerpc" "AUTOGEN_pidl")

for i in "${disable_options[@]}"
do
	sed -i -e "/$i/ s/ON/OFF/" ./CMakeOptions.txt
done
