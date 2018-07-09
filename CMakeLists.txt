cmake_minimum_required (VERSION 3.11)
project(hdmi_cec_analyzer)

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

add_library(hdmi_cec_analyzer SHARED ${SOURCES})
target_link_libraries(hdmi_cec_analyzer PRIVATE Saleae::AnalyzerSDK)

if(MSVC)
    install(TARGETS hdmi_cec_analyzer RUNTIME DESTINATION "Analyzers")
else()
    install(TARGETS hdmi_cec_analyzer LIBRARY DESTINATION "Analyzers")
endif()

set_post_build_destination(hdmi_cec_analyzer)
