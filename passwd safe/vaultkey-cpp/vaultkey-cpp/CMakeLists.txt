cmake_minimum_required(VERSION 3.19)
project(VaultKey LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# ---------------------------------------------------------------------------
# Dependencies
#   Qt6: Core, Widgets, WebEngineWidgets, WebChannel
#   OpenSSL: AES-256-GCM (EVP interface)
#   libargon2: Argon2id password hashing + raw KDF (same params as the
#              Python argon2-cffi build, so it can read the existing vault.db)
#   SQLite3: storage (linked directly via the C API, no ORM)
#
# Install on Ubuntu/Debian:
#   sudo apt install qt6-base-dev qt6-webengine-dev libqt6webenginewidgets6 \
#                     libqt6webchannel6-dev libargon2-dev libssl-dev libsqlite3-dev
#
# Install on macOS (Homebrew):
#   brew install qt argon2 openssl sqlite
#
# Install on Windows: use vcpkg
#   vcpkg install qt6-base qt6-webengine qt6-webchannel argon2 openssl sqlite3
# ---------------------------------------------------------------------------

find_package(Qt6 REQUIRED COMPONENTS Core Widgets WebEngineWidgets WebChannel)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

find_path(ARGON2_INCLUDE_DIR argon2.h)
find_library(ARGON2_LIBRARY NAMES argon2)
if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
    message(FATAL_ERROR "libargon2 not found - install libargon2-dev (Linux), argon2 (Homebrew), or the vcpkg 'argon2' port.")
endif()

add_executable(vaultkey
    src/main.cpp
    src/backend.cpp
    src/backend.h
    src/database.cpp
    src/database.h
)

target_include_directories(vaultkey PRIVATE ${ARGON2_INCLUDE_DIR})

target_link_libraries(vaultkey PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::WebEngineWidgets
    Qt6::WebChannel
    OpenSSL::Crypto
    SQLite::SQLite3
    ${ARGON2_LIBRARY}
)

# Ship the UI files and the SQLite db next to the built binary so
# QUrl::fromLocalFile(...) finds them without extra path juggling.
add_custom_command(TARGET vaultkey POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/../login.html $<TARGET_FILE_DIR:vaultkey>/login.html
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/../dashboard.html $<TARGET_FILE_DIR:vaultkey>/dashboard.html
)
