#!/bin/bash
set -e # Exit on error

# --- Get package info robustly ---
if ! dpkg-parsechangelog --file debian/changelog &> /dev/null; then
    echo "Error: Cannot parse debian/changelog. Are you in the project root?" >&2
    exit 1
fi
PACKAGE_NAME=$(dpkg-parsechangelog --file debian/changelog -S Source)
UPSTREAM_VERSION=$(dpkg-parsechangelog --file debian/changelog -S Version | sed 's/-[0-9]\+.*$//') # Handle -1ubuntu1 etc.
DEBIAN_REVISION=$(dpkg-parsechangelog --file debian/changelog -S Version | sed -n 's/^[0-9.]\+-\([0-9]\+.*\)$/\1/p')

if [ -z "$PACKAGE_NAME" ] || [ -z "$UPSTREAM_VERSION" ]; then
    echo "Error: Could not determine package name or upstream version from debian/changelog." >&2
    exit 1
fi

ORIG_TARBALL_FILENAME="${PACKAGE_NAME}_${UPSTREAM_VERSION}.orig.tar.gz"
ORIG_TARBALL_PATH="../${ORIG_TARBALL_FILENAME}"
PROJECT_DIR_NAME=$(basename "$PWD") # Get name of current dir

# Sanity check directory name vs package name
if [ "$PROJECT_DIR_NAME" != "$PACKAGE_NAME" ]; then
    echo "Warning: Project directory name ('${PROJECT_DIR_NAME}') does not match package name ('${PACKAGE_NAME}'). Tarball creation might be incorrect." >&2
    # Consider exiting here if this mismatch is critical
fi

echo "Starting Debian package build for ${PACKAGE_NAME} version ${UPSTREAM_VERSION}-${DEBIAN_REVISION}..."
echo "(Project directory: $PWD)"

# --- 1. Clean previous build artifacts ---
echo "Cleaning previous build artifacts..."
if [ -f debian/rules ] && [ -x debian/rules ]; then
    fakeroot debian/rules clean || echo "Warning: 'debian/rules clean' failed, continuing build..."
else
    echo "Warning: debian/rules not found or not executable, skipping clean via rules."
fi
echo "Removing potential leftover package files from ../"
rm -f "../${PACKAGE_NAME}_${UPSTREAM_VERSION}-"*.debian.tar.* \
      "../${PACKAGE_NAME}_${UPSTREAM_VERSION}-"*.dsc \
      "../${PACKAGE_NAME}_"*.buildinfo \
      "../${PACKAGE_NAME}_"*.changes \
      "../${PACKAGE_NAME}_"*.deb \
      "../${PACKAGE_NAME}_"*.ddeb \
      "${ORIG_TARBALL_PATH}"
echo "Clean done."

# --- 2. Create upstream tarball ---
PARENT_DIR_ABS=$(realpath ../)
echo "Checking writability of parent directory: ${PARENT_DIR_ABS}"
if [ ! -w "${PARENT_DIR_ABS}" ]; then
    echo "Error: Parent directory ${PARENT_DIR_ABS} is not writable." >&2
    exit 1
fi

echo "Creating upstream tarball: ${ORIG_TARBALL_PATH}"
echo "(Moving to parent directory: ${PARENT_DIR_ABS})"

ORIG_PWD=$PWD
cd ..

# Use tar with excludes relative to the parent directory
echo "Running tar from: $(pwd)"
tar --exclude="${PROJECT_DIR_NAME}/debian" \
    --exclude="${PROJECT_DIR_NAME}/.git" \
   -czvf "${ORIG_TARBALL_FILENAME}" "${PROJECT_DIR_NAME}/"

# Check if tarball was created
if [ ! -f "${ORIG_TARBALL_FILENAME}" ]; then
   echo "Error: Failed to create upstream tarball ${ORIG_TARBALL_FILENAME}" >&2
   # Attempt to go back to project directory before exiting
   cd "${ORIG_PWD}" || exit 1
   exit 1
fi

# Go back to project directory
cd "${ORIG_PWD}"
echo "Upstream tarball created. Returned to $(pwd)."

# --- 3. Build the package ---
echo "Running dpkg-buildpackage..."
# Pass any extra arguments (e.g., -b) from the command line
dpkg-buildpackage -us -uc "$@"
echo "dpkg-buildpackage finished."

# --- 4. List generated files ---
echo "Generated files in ../:"
ls -l "../${PACKAGE_NAME}_${UPSTREAM_VERSION}"*

echo "Build script completed successfully."
exit 0
