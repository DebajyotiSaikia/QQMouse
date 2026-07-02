cmake_minimum_required(VERSION 3.20)
project(Skittermouse VERSION 0.1.0 LANGUAGES CXX)

# --- Global C++ settings -----------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

option(SM_BUILD_TESTS "Build Skittermouse unit tests" ON)

# --- core: pure logic, NO platform / OS includes (spec Section 2.2, 16) ------
# This library MUST compile and be unit-testable without any Win32 or Cocoa
# headers. Anything OS-specific belongs in src/platform/, behind an interface.
add_library(skittermouse_core STATIC
    src/core/ownership_state.cpp
    src/core/server_election.cpp
    src/core/config.cpp
    src/core/key_translation.cpp
    src/core/input_tracker.cpp
    src/core/clipboard_sync.cpp
    src/core/heartbeat.cpp
    src/core/input_pipeline.cpp
    src/net/message_codec.cpp
)
target_include_directories(skittermouse_core PUBLIC src)
target_compile_features(skittermouse_core PUBLIC cxx_std_17)

# --- platform layer: per-OS source gating from day one (spec Section 16) -----
# .mm (Objective-C++) sources must NEVER reach the Windows toolchain, and Win32
# .cpp sources must never reach the macOS toolchain. Populate these lists as the
# platform/ files are added, following the build order in Section 17.
#
# Portable, platform-agnostic building blocks (standard C++ only) live here too,
# e.g. HKDF layered on top of the platform HMAC (spec Section 7.1).
set(SM_PLATFORM_SOURCES
    src/crypto/hkdf.cpp
    src/crypto/base64.cpp
    src/pairing/verification_code.cpp
    src/pairing/ecdh_handshake.cpp
    src/pairing/key_store.cpp
    src/net/session_token.cpp
    src/net/ws_frame.cpp
    src/net/ws_handshake.cpp
    src/net/frame_assembler.cpp
    src/net/wol_sender.cpp
    src/net/discovery_beacon.cpp
    src/net/discovery_table.cpp
)
if(WIN32)
    list(APPEND SM_PLATFORM_SOURCES
        src/platform/crypto_win.cpp       # Sections 5.4/7: AES-256-GCM, ECDH, HMAC via CNG/BCrypt
        src/platform/inject_win.cpp       # Section 3.2: SendInput
        src/platform/capture_win.cpp      # Section 3.1: WH_MOUSE_LL + WH_KEYBOARD_LL
        src/platform/ws_transport_win.cpp # Section 5.1: TCP + WebSocket client transport
        src/platform/lock_win.cpp         # Section 14: LockWorkStation
        # ... added as sections land
    )
elseif(APPLE)
    enable_language(OBJCXX)
    list(APPEND SM_PLATFORM_SOURCES
        # macOS native backends are not implemented yet (see todo.md, Step 6). The
        # portable sources above still compile here; the app stub links only what it
        # references, so no macOS crypto symbols are required for the stub build.
        # src/platform/crypto_mac.mm      # Sections 5.4/7: CommonCrypto + Security.framework
        # src/platform/capture_mac.mm     # Section 3.1
    )
endif()

# All OS-specific code compiles into one library that BOTH the app and the tests
# link, so headless CI tests can still exercise the crypto/net seams directly.
add_library(skittermouse_platform STATIC ${SM_PLATFORM_SOURCES})
target_include_directories(skittermouse_platform PUBLIC src)
target_link_libraries(skittermouse_platform PUBLIC skittermouse_core)
if(WIN32)
    # All native, zero third-party (Section 16): bcrypt now (Sections 5.4/7); later
    # ws2_32 (Sections 5/6), shell/comctl (Section 10), etc.
    target_link_libraries(skittermouse_platform PUBLIC bcrypt ws2_32 user32)
elseif(APPLE)
    target_link_libraries(skittermouse_platform PUBLIC
        "-framework Security" "-framework CoreFoundation")
endif()

# --- app executable ----------------------------------------------------------
add_executable(skittermouse
    src/main.cpp
)
target_link_libraries(skittermouse PRIVATE skittermouse_platform)

if(WIN32)
    # Embed our own application icon (shown in Explorer, the taskbar, and Alt-Tab,
    # and reused as the installer icon below). Compact ~20 KB PNG-frame .ico --
    # packaging/skittermouse.ico referenced by packaging/skittermouse.rc.
    target_sources(skittermouse PRIVATE packaging/skittermouse.rc)
    target_include_directories(skittermouse PRIVATE packaging)
endif()

# --- tests -------------------------------------------------------------------
if(SM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# --- packaging: native installers via CPack ----------------------------------
# Windows -> NSIS (.exe installer); macOS -> DragNDrop (.dmg). Both are produced
# by the nightly-release workflow (.github/workflows/nightly-release.yml) and
# published to the rolling "nightly" GitHub Release the website links to.
install(TARGETS skittermouse RUNTIME DESTINATION bin)

set(CPACK_PACKAGE_NAME "Skittermouse")
set(CPACK_PACKAGE_VENDOR "Skittermouse")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Software KVM: control multiple computers with one mouse and keyboard")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Skittermouse")

# Create Start-Menu (and Desktop) shortcuts so the app is findable after install.
# Format: <exe-name-without-.exe> <Start-Menu label>. NSIS looks for the exe under
# the install tree's bin/ (matching install(TARGETS ... RUNTIME DESTINATION bin)).
set(CPACK_PACKAGE_EXECUTABLES "skittermouse" "Skittermouse")
set(CPACK_CREATE_DESKTOP_LINKS "skittermouse")

# Terms the user must accept during installation, packaged into both installers:
# NSIS shows a license page gated by an "I Agree" button; the macOS DMG shows a
# software license agreement (SLA) that must be accepted before it will mount.
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/EULA.txt")

if(WIN32)
    set(CPACK_GENERATOR "NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "Skittermouse")
    set(CPACK_NSIS_PACKAGE_NAME "Skittermouse")
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
    # Our own icon on the installer/uninstaller and the Add/Remove Programs entry.
    set(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}/packaging/skittermouse.ico")
    set(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}/packaging/skittermouse.ico")
    # Quadruple backslash on purpose: CMake collapses it to two, CPack writes those
    # two verbatim into CPackConfig.cmake, and cpack re-parses them to the single
    # backslash NSIS needs ($INSTDIR\bin\skittermouse.exe). Two backslashes here
    # would collapse to one and make CPackConfig.cmake fail with "invalid escape \s".
    set(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\skittermouse.exe")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE ON)
    set(CPACK_DMG_SLA_LANGUAGES "English")
endif()

include(CPack)
