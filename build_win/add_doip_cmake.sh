#
# This script adjusts the CMakeLists.txt to add the doip plugin to the build
# It inserts plugins/doip after the docsis plugin
#
sed -i -e "/plugins\/docsis/a \\\t\tplugins\/doip" ./CMakeLists.txt
