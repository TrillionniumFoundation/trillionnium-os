# Android build-host module-contract consumer

This directory verifies the exact checked-in valid and invalid vectors consumed
by Android packaging/build tooling. It is source-only: it does not claim a Soong
image build, SELinux compilation, installation, a physical device or release.
The L3 image lane must separately prove that the selected generated contracts and
installed binaries agree.
