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
    src/core/hotkey.cpp
    src/core/wake_flow.cpp
    src/core/log.cpp
    src/ui/menu_model.cpp
    src/net/message_codec.cpp
    src/net/file_transfer.cpp
    src/net/file_session.cpp
    src/net/file_channel.cpp
    src/net/file_promise_announce.cpp
    src/net/ownership_codec.cpp
    src/net/peer_hello.cpp
    src/app/mesh_node.cpp
    src/app/connection_manager.cpp
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
    src/pairing/pairing_exchange.cpp
    src/pairing/key_store.cpp
    src/app/secure_link.cpp
    src/app/connection_service.cpp
    src/net/session_token.cpp
    src/net/ws_frame.cpp
    src/net/ws_handshake.cpp
    src/net/frame_assembler.cpp
    src/net/wol_sender.cpp
    src/net/discovery_beacon.cpp
    src/net/discovery_table.cpp
    src/net/discovery_socket.cpp
)
if(WIN32)
    list(APPEND SM_PLATFORM_SOURCES
        src/platform/crypto_win.cpp       # Sections 5.4/7: AES-256-GCM, ECDH, HMAC via CNG/BCrypt
        src/platform/inject_win.cpp       # Section 3.2: SendInput
        src/platform/capture_win.cpp      # Section 3.1: WH_MOUSE_LL + WH_KEYBOARD_LL
        src/platform/ws_transport_win.cpp # Section 5.1: TCP + WebSocket client transport
        src/platform/lock_win.cpp         # Section 14: LockWorkStation
        src/platform/clipboard_win.cpp    # Section 8: CF_UNICODETEXT + exclusion check
        src/platform/filepromise_win.cpp  # Section 9.1: IDataObject delay-render file promise
        src/platform/autostart_win.cpp    # Section 13: Task Scheduler, elevated
        src/platform/tray_win.cpp         # Section 10: Shell_NotifyIcon tray app shell
        src/ui/picker_window_win.cpp      # Section 4.2: hotkey-triggered machine picker
        src/ui/settings_window_win.cpp    # Section 10: native settings window
        src/platform/wol_diag_win.cpp     # Section 12: powercfg WoL self-diagnosis
        src/pairing/pairing_dialog_win.cpp # Section 7.1: numeric-comparison confirm dialog
        # ... added as sections land
    )
elseif(APPLE)
    enable_language(OBJCXX)
    list(APPEND SM_PLATFORM_SOURCES
        src/platform/inject_mac.mm        # Section 3.2: CGEventPost
        src/platform/capture_mac.mm       # Section 3.1: CGEventTapCreate
        src/platform/lock_mac.mm          # Section 14: CGSession suspend
        src/platform/clipboard_mac.mm     # Section 8: NSPasteboard
        src/platform/autostart_mac.mm     # Section 13: LaunchAgent plist
        src/platform/crypto_mac.mm        # Sections 5.4/7: CommonCrypto + Security.framework
        src/platform/tray_mac.mm          # Section 10: NSStatusBar tray app shell
        src/platform/hotkey_mac.mm        # Section 4.1: Carbon RegisterEventHotKey global hotkey
        src/ui/picker_window_mac.mm       # Section 4.2: topmost NSPanel machine picker
        src/ui/settings_window_mac.mm     # Section 10: native settings window
        src/pairing/pairing_dialog_mac.mm # Section 7.1: NSAlert confirm dialog
    )
else()
    # Linux: TEST RIG ONLY (headless two-container network validation, tests/docker/).
    # POSIX WS transport + OpenSSL-backed crypto. OpenSSL is NOT used by the shipped
    # Windows/macOS product (which uses BCrypt / CommonCrypto per spec 16) -- see the
    # header of src/platform/crypto_posix.cpp.
    list(APPEND SM_PLATFORM_SOURCES
        src/platform/crypto_posix.cpp
        src/platform/ws_transport_posix.cpp
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
    target_link_libraries(skittermouse_platform PUBLIC bcrypt ws2_32 user32 shell32 secur32 crypt32 ole32 iphlpapi)
elseif(APPLE)
    target_link_libraries(skittermouse_platform PUBLIC
        "-framework Security" "-framework CoreFoundation" "-framework CoreGraphics"
        "-framework AppKit" "-framework Foundation" "-framework Carbon")
else()
    # Linux test rig only: OpenSSL supplies crypto where no native system API exists.
    find_package(OpenSSL REQUIRED)
    target_link_libraries(skittermouse_platform PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

# --- app executable ----------------------------------------------------------
# WIN32 -> GUI subsystem on Windows (wWinMain, no console window for the tray app);
# ignored on other platforms (main() is used).
add_executable(skittermouse WIN32
    src/main.cpp
)
target_link_libraries(skittermouse PRIVATE skittermouse_platform)

# --- netcheck: headless two-container network-validation harness (Linux rig only) -
# Runs the real secure_link -> ConnectionManager -> MeshNode path over a live TCP/WS
# socket between two containers (tests/docker/). Not shipped.
if(UNIX AND NOT APPLE)
    add_executable(netcheck tools/netcheck.cpp)
    target_link_libraries(netcheck PRIVATE skittermouse_platform)
    add_executable(netpair tools/netpair.cpp)
    target_link_libraries(netpair PRIVATE skittermouse_platform)
    add_executable(netfile tools/netfile.cpp)
    target_link_libraries(netfile PRIVATE skittermouse_platform)
endif()

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
install(TARGETS skittermouse RUNTIME DESTINATION bin COMPONENT application)

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

    # Finish page: a "Run Skittermouse" checkbox, CHECKED by default, launches the app
    # right after install (relative to $INSTDIR; quad backslash -> one, per above).
    set(CPACK_NSIS_MUI_FINISHPAGE_RUN "bin\\\\skittermouse.exe")

    # Optional "Run on startup" component -- UNCHECKED by default (spec 13: opt-in so a
    # reboot always recovers). When ticked it installs a marker file; the NSIS command
    # below then drops a shortcut into the user's Startup folder. Single-quoted NSIS
    # strings avoid double-quote escaping; quad backslash -> one in the final script.
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/startup.marker"
            DESTINATION bin COMPONENT startup)
    set(CPACK_COMPONENTS_ALL application startup)
    set(CPACK_COMPONENT_APPLICATION_HIDDEN TRUE)
    set(CPACK_COMPONENT_APPLICATION_REQUIRED TRUE)
    set(CPACK_COMPONENT_STARTUP_DISPLAY_NAME "Run on startup")
    set(CPACK_COMPONENT_STARTUP_DESCRIPTION
        "Start Skittermouse automatically when you log in (you can change this later in the tray).")
    set(CPACK_COMPONENT_STARTUP_DISABLED TRUE)
    # On install: open the app's ports in Windows Firewall (port-based rules avoid any
    # quote-escaping through CMake->CPack->NSIS), then optionally drop the Startup
    # shortcut if the "Run on startup" component was ticked.
    set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "
      nsExec::Exec 'netsh advfirewall firewall delete rule name=Skittermouse'
      nsExec::Exec 'netsh advfirewall firewall delete rule name=SkittermouseUDP'
      nsExec::Exec 'netsh advfirewall firewall add rule name=Skittermouse dir=in action=allow protocol=TCP localport=47800-47803'
      nsExec::Exec 'netsh advfirewall firewall add rule name=SkittermouseUDP dir=in action=allow protocol=UDP localport=47802'
      IfFileExists '$INSTDIR\\\\bin\\\\startup.marker' 0 +2
        CreateShortCut '$SMSTARTUP\\\\Skittermouse.lnk' '$INSTDIR\\\\bin\\\\skittermouse.exe'
    ")
    # On uninstall (which also runs before a reinstall): stop any running instance so
    # the exe isn't locked, then remove the firewall rules + Startup shortcut.
    set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "
      nsExec::Exec 'taskkill /IM skittermouse.exe /F'
      nsExec::Exec 'netsh advfirewall firewall delete rule name=Skittermouse'
      nsExec::Exec 'netsh advfirewall firewall delete rule name=SkittermouseUDP'
      Delete '$SMSTARTUP\\\\Skittermouse.lnk'
    ")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
    set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE ON)
    set(CPACK_DMG_SLA_LANGUAGES "English")
endif()

include(CPack)
