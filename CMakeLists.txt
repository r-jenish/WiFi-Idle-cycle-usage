# CMakeLists.txt

cmake_minimum_required(VERSION 2.8)
project( PROJECTNAME )
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package( PCAP REQUIRED )
add_executable( wifi-math main.cpp util.cpp client.cpp )
target_link_libraries( wifi-math-server ${PCAP_LIBRARY} )
