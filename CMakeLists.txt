cmake_minimum_required(VERSION 3.17.5)
project(macos_compatibility)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(osquery REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

# Add the extension executable
add_executable(macos_compatibility src/macos_compatibility.cpp)

# Link against osquery's SDK library
target_link_libraries(macos_compatibility PRIVATE 
  osquery::osquerycore
  osquery::osquerysdk
  CURL::libcurl
  nlohmann_json::nlohmann_json
)

# Set include directories
target_include_directories(macos_compatibility PRIVATE 
  ${osquery_INCLUDE_DIRS}
  ${CURL_INCLUDE_DIRS}
)

# Set installation path
install(TARGETS macos_compatibility DESTINATION bin)
