# Magisk Build Environment Setup on Ubuntu 24.04

This guide provides step-by-step instructions to configure an Android build environment on Ubuntu 24.04.

---

## 1. Install Android Studio and SDK

Download and install Android Studio from [https://developer.android.com/studio](https://developer.android.com/studio).

Extract and move it to `/opt`:

```bash
cd ~/Downloads
tar -xvzf android-studio-*.tar.gz
sudo mv android-studio /opt/
/opt/android-studio/bin/studio.sh
```

---

## 2. Set Up Android SDK Environment Variables

Make sure the SDK is installed. Then:

```bash
ls ~/Android/Sdk
echo 'export ANDROID_HOME=$HOME/Android/Sdk' >> ~/.bashrc
echo 'export PATH=$PATH:$ANDROID_HOME/platform-tools' >> ~/.bashrc
source ~/.bashrc
```

Verify:

```bash
echo $ANDROID_HOME
# Expected output: /home/vboxuser/Android/Sdk
```

---

## 3. Build Using Python

Navigate to the `Magisk` directory and build:

```bash
cd Magisk
python3 build.py ndk
```

---

## 4. Install Rust and Cargo

Install Rust using the official installer:

```bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
cargo --version
```

---

## 5. Update Git Submodules

Make sure all submodules are initialized:

```bash
git submodule update --init --recursive
```

> ⚠️ Your virtual machine should have at least **6GB to 8GB of RAM**.

---

## 6. Clean Rust Output and Configure Android Studio Path

Remove the previous Rust output and set the Android Studio path:

```bash
rm -rf native/out/rust
echo 'export ANDROID_STUDIO=/opt/android-studio' >> ~/.bashrc
source ~/.bashrc
```

---

## 7. Build the Entire Project

Ensure the Gradle wrapper is executable and run the full build:

```bash
chmod +x gradlew
python3 build.py all
```
