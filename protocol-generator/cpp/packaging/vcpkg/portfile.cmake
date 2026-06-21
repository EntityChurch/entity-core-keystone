# vcpkg portfile for entity-core-protocol-cpp (S5 packaging, A-CPP-016).
#
# AUTHORED + version-pinned, NOT submitted to the vcpkg registry. Publishing is
# an operator action (lifecycle Publishing). Consume as an overlay port:
#
#     vcpkg install entity-core-protocol --overlay-ports=packaging/vcpkg
#
# This port builds the in-repo source via the project CMakeLists. On a real
# publish the SOURCE_PATH below becomes a `vcpkg_from_github(... REF v0.1.0 SHA512 ...)`
# fetch of the tagged release tarball — the `repository_url` + tag + tarball hash
# are TBD on first publish (profile [publishing].repository_url is empty until then,
# A-CPP-016). For the in-repo/overlay path we point at the peer source directory.
#
# SPDX-License-Identifier: Apache-2.0

# In-repo overlay: the port source IS this peer's tree (two dirs up from the port).
# On publish, replace this block with vcpkg_from_github(REPO ... REF v0.1.0 SHA512 ...).
get_filename_component(SOURCE_PATH "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DEC_SANITIZE=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
    PACKAGE_NAME EntityCoreProtocol
    CONFIG_PATH lib/cmake/EntityCoreProtocol
)

# Headers ship once (under include/); drop the duplicate in the debug tree.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
