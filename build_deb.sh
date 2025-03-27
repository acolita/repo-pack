#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
PACKAGE_NAME=$(dpkg-parsechangelog -S Source)
UPSTREAM_VERSION=$(dpkg-parsechangelog -S Version | sed 's/-[0-9]\+$//') # Extract version part before Debian revision
ORIG_TARBALL="../${PACKAGE_NAME}_${UPSTREAM_VERSION}.orig.tar.gz"

# --- Script Start ---
echo "Starting Debian package build for ${PACKAGE_NAME} version ${UPSTREAM_VERSION}..."

# 1. Clean previous build artifacts
echo "Cleaning previous build artifacts..."
if [ -f debian/rules ]; then
    fakeroot debian/rules clean
else
    echo "Warning: debian/rules not found, skipping clean via rules."
fi
# Clean potential leftovers in parent dir
rm -f ../${PACKAGE_NAME}_*.debian.tar.* ../${PACKAGE_NAME}_*.dsc ../${PACKAGE_NAME}_*.buildinfo ../${PACKAGE_NAME}_*.changes ../${PACKAGE_NAME}_*.deb ../${PACKAGE_NAME}_*.ddeb "${ORIG_TARBALL}"
echo "Clean done."

# 2. Create upstream tarball
echo "Creating upstream tarball: ${ORIG_TARBALL}"
# Go to parent directory to create tarball correctly
cd ..
tar --exclude="./${PACKAGE_NAME}/debian" --exclude="./${PACKAGE_NAME}/.git" -czvf "${ORIG_TARBALL}" "${PACKAGE_NAME}/"
# Go back to project directory
cd "${PACKAGE_NAME}"
echo "Upstream tarball created."

# 3. Build the package
echo "Running dpkg-buildpackage..."
dpkg-buildpackage -us -uc "$@" # Pass any extra arguments like -b for binary-only
echo "dpkg-buildpackage finished."

# 4. List generated files
echo "Generated files in ../:"
ls -l "../${PACKAGE_NAME}_${UPSTREAM_VERSION}"*

echo "Build script completed successfully."
exit 0
