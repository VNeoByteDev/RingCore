cmake_minimum_required(VERSION 3.20)
project(RingCoreGuardian VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt 设置
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Svg Network)

set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/panels/ScanPanel.cpp
    src/panels/ProcessPanel.cpp
    src/panels/FirewallPanel.cpp
    src/panels/JunkCleanPanel.cpp
    src/panels/SettingPanel.cpp
    src/panels/HomePanel.cpp
    src/widgets/StatusCard.cpp
    src/widgets/ScanWidget.cpp
    src/core/ServiceClient.cpp
    src/core/ThreatDB.cpp
    src/core/HeuristicEngine.cpp
    src/core/Settings.cpp
    src/core/JunkCleaner.cpp
    src/core/QuarantineManager.cpp
    src/engine/ShieldEngine.cpp
    resources/app.rc
)

set(HEADERS
    src/MainWindow.h
    src/panels/ScanPanel.h
    src/panels/ProcessPanel.h
    src/panels/FirewallPanel.h
    src/panels/JunkCleanPanel.h
    src/panels/SettingPanel.h
    src/panels/HomePanel.h
    src/widgets/StatusCard.h
    src/widgets/ScanWidget.h
    src/core/ServiceClient.h
    src/core/ThreatDB.h
    src/core/HeuristicEngine.h
    src/core/Settings.h
    src/core/JunkCleaner.h
    src/engine/ShieldEngine.h
)

set(RESOURCES
    resources/resources.qrc
)

add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS} ${RESOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Widgets Qt6::Svg Qt6::Network bcrypt)

# 设置 Windows 子系统为 WINDOWS (不显示控制台)
set_target_properties(${PROJECT_NAME} PROPERTIES
    WIN32_EXECUTABLE TRUE
    LINK_FLAGS "/SUBSYSTEM:WINDOWS"
)

# 安装规则
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# ── 自动复制 Qt DLL 到输出目录 ──
# 使用 Qt6 内置的 windeployqt 工具
find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${Qt6_DIR}/../../../bin")
if(WINDEPLOYQT_EXECUTABLE)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --no-translations
            --no-opengl-sw
            "$<TARGET_FILE:${PROJECT_NAME}>"
        COMMENT "Running windeployqt to copy Qt dependencies..."
    )
endif()

# 复制 plugins 子目录 (platforms, styles, imageformats)
set(QT_PLUGINS_DIR "${Qt6_DIR}/../../../plugins")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${QT_PLUGINS_DIR}/platforms/qwindows.dll"
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms/"
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${PROJECT_NAME}>/styles"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${QT_PLUGINS_DIR}/styles/qmodernwindowsstyle.dll"
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>/styles/"
    COMMENT "Copying Qt platform plugins..."
)
