cmake_minimum_required (VERSION 3.11)
project(hdmi_cec_analyzer)

add_definitions( -DLOGIC2 )

set(CMAKE_OSX_DEPLOYMENT_TARGET "10.14" CACHE STRING "Minimum supported MacOS version" FORCE)

# enable generation of compile_commands.json, helpful for IDEs to locate include files.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# custom CMake Modules are located in the cmake directory.
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include(ExternalAnalyzerSDK)

set(SOURCES 
src/HdmiCecAnalyzer.cpp
src/HdmiCecAnalyzer.h
src/HdmiCecAnalyzerResults.cpp
src/HdmiCecAnalyzerResults.h
src/HdmiCecAnalyzerSettings.cpp
src/HdmiCecAnalyzerSettings.h
src/HdmiCecProtocol.cpp
src/HdmiCecProtocol.h
src/HdmiCecSimulationDataGenerator.cpp
src/HdmiCecSimulationDataGenerator.h
)

add_analyzer_plugin(hdmi_cec_analyzer SOURCES ${SOURCES})
