
# Microchip PolarFire SoC Linux Software Development Kit
This repository builds a command line only RISC-V Linux image for the Microchip PolarFire SoC Development Boards.
It first will build the GNU cross-compilation toolchain for RISC-V, which will be installed in the `toolchain/` subdirectory. This toolchain is then used to build a Linux image consisting of the kernel, a Busybox based root file system and the necessary bootloaders for each development platform.

Currently the following development platforms are supported:
- [MPFS-DEV-KIT](https://github.com/polarfire-soc/polarfire-soc-documentation/blob/master/boards/mpfs-dev-kit/MPFS-DEV-KIT_user_guide.md) (HiFive Unleashed Expansion Board)
- Icicle Kit (Engineering Sample) (Requires minimum FPGA design: [v2021.08](https://github.com/polarfire-soc/icicle-kit-reference-design/releases/tag/2021.08). Designs prior to this release use a different memory map and will fail to boot.)

The complete User Guides for each development platform, containing board and boot instructions, are available in the [polarfire-soc documentation repository](https://github.com/polarfire-soc/polarfire-soc-documentation). 


## Building Linux Using Buildroot
This section describes the procedure to build the Linux boot image and load it onto an SD card or eMMC using Buildroot. Please check the [Supported Build Hosts](#supported-build-hosts) and the [Prerequisite Packages](#prerequisite-packages) before continuing.

### Build instructions
The following commands checkout the Software Development Kit (SDK) in a new directory:
```
git clone https://github.com/polarfire-soc/polarfire-soc-buildroot-sdk.git
cd polarfire-soc-buildroot-sdk
git checkout master
```
Before building for the first time (or if updating to the latest version), the contents of the sub-modules must be acquired:
```
git submodule sync
git submodule update --init --recursive
```
Then the Linux image can be built in the `work` sub-directory:
```
unset RISCV
make all DEVKIT=icicle-kit-es
```

The `DEVKIT` option can be used to set the target board for which linux is built, and if left blank it will default to `DEVKIT=icicle-kit-es`. 

The following table details the available targets:

| `DEVKIT` | Board Name |
| --- | --- |
| `DEVKIT=mpfs` | MPFS-DEV-KIT (HiFive Unleashed Expansion Board) |
| `DEVKIT=icicle-kit-es` | Icicle Development Kit with engineering sample silicon |
| `DEVKIT=icicle-kit-es-amp` | Icicle Development Kit with engineering sample silicon running in AMP mode |

The `icicle-kit-es-amp` target can be used to build the Icicle Development using a Linux + FreeRTOS AMP configuration demo. Please see the [Asymmetric Multiprocessing (AMP)](https://github.com/polarfire-soc/polarfire-soc-documentation/blob/master/asymmetric-multiprocessing/amp.md) documentation for further information.

To boot Linux on your board using this image, see: [Loading the Image onto the Target](#Loading-the-Image-onto-the-Target).

Note: The first time the build is run it can take a long time, as it also builds the RISC-V cross compiler toolchain. 

The output file contains the first stage bootloader, the root file system and an image containing the linux kernel, device tree blob & second stage bootloader.           
The source for the device tree for the MPFS DEV-KIT (HiFive Unleashed Expansion Board) board is available in `conf/mpfs/mpfs.dts`.       
For other boards, the source is located in `linux/arch/riscv/boot/dts/microchip`.                  
The configuration options used for the Linux kernel are in `linux/arch/riscv/configs/<devkit>_defconfig`.     
`conf/<devkit>` contains the U-Boot and buildroot initramfs config files.

### Rebuilding the Linux Image
If you need to rebuild your image or change the board being targeted, type the following from the top level directory of the polarfire-soc-buildroot-sdk:
```
$ make clean
$ make all DEVKIT=<devkit>
```

## Building Linux + seL4 AMP image
Created HSS payload and initamfs images run seL4 on hart1 and Linux on harts 2-4. Related memory e.g. configuration is defined in `conf/icicle-kit-es-sel4/dts/microchip-mpfs-icicle-kit.dts` Similar configuration is applied via Linux device tree `linux/arch/riscv/boot/dts/microchip/microchip-mpfs-icicle-kit-sel4.dts`.

To build images use command
```
$ make all DEVKIT=icicle-kit-es-sel4 SEL4_BIN=<path_to_seL4_binary>
```

Build script copies seL4 image from `SEL4_BIN` to `$(buildroot_initramfs_wrkdir)/images`-directory.

## Building buildroot sel4-tool package with local source
Modify `conf/icicle-kit-es-sel4/local.mk`. Change `SEL4_TOOL_OVERRIDE_SRCDIR` to point local folder with sel4-tool package sources.

First make command is needed only when local.mk is updated
```
$ make DEVKIT=icicle-kit-es-sel4 buildroot_pkg_override
$ make DEVKIT=icicle-kit-es-sel4 sel4-tool-rebuild
$ make all DEVKIT=icicle-kit-es-sel4 SEL4_BIN=<path_to_seL4_binary>
```

## Building HSS

Install SoftConsole (v2021.1) and find out SoftConsole installation dir (SC_INSTALL_DIR).

Install Libero SoC (v2021.1) and find out fpgenprog location `<LIBERO_SOC_DIR>/Libero/bin64/fpgenprog` (FPGENPROG).

Build HSS binary (see `README` in https://github.com/polarfire-soc/hart-software-services).

Make sure to use the `8.3.0` version for `riscv64-unknown-elf-gcc`.
```
$ riscv64-unknown-elf-gcc --version
riscv64-unknown-elf-gcc (xPack GNU RISC-V Embedded GCC (Microsemi SoftConsole build), 64-bit) 8.3.0
Copyright (C) 2018 Free Software Foundation, Inc.
```
```
# Go to hart-software-services workarea
$ cd <hart-software-services>

# Set tool paths
$ export SC_INSTALL_DIR=<SOFTCONSOLE_DIR>
$ export FPGENPROG=<LIBERO_SOC_DIR>/Libero/bin64/fpgenprog

# Second elf-file in build output dir causes problems
$ rm Default/hss-l2lim.elf

$ $SC_INSTALL_DIR/eclipse/jre/bin/java -jar $SC_INSTALL_DIR/extras/mpfs/mpfsBootmodeProgrammer.jar --workdir $PWD/Default --die MPFS250T_ES --package FCVG484 --bootmode 1
```


## Loading the Image onto the Target
The instructions for the [eMMC on the Icicle Kit can be found here](#Preparing-the-eMMC-for-the-Icicle-Kit), for the [SD card on the Icicle Kit here](#Preparing-an-SD-Card-for-the-Icicle-Kit) and for the [the MPFS here](#Preparing-an-SD-Card-for-MPFS).

### Preparing the eMMC for the Icicle Kit
If the HSS is not present in eNVM, using the y-modem loader, transfer the HSS to eNVM on the Icicle kit.      
Connect to UART0 (J11), and power on the board. Settings are 115200 baud, 8 data bits, 1 stop bit, no parity, and no flow control. Press a key to stop automatic boot. In the HSS console, type `usbdmsc` to expose the eMMC as a block device.          
Connect the board to your host PC using J16, located beside the SD card slot.

Once this is complete, on the host PC, use `dmesg` to check what the drive identifier for the onboard eMMC is.
```
$ dmesg | egrep "sd|mmcblk"
```
The output should contain a line similar to one of the following lines:
```
[85089.431896] sd 6:0:0:2: [sdX] 31116288 512-byte logical blocks: (15.9 GB/14.8 GiB)
[51273.539768] mmcblkX: mmc0:0001 EB1QT 29.8 GiB 
```
`sdX` or `mmcblkX` is the drive identifier that should be used in the following commands, where `X` should be replaced with the specific character from the output of the previous command.           
For these examples the identifier `sdX` is used. 

#### WARNING:              
        The drive with the identifier `sda` is the default location for your operating system.        
        DO NOT pass this identifier to any of the commands listed here without being absolutely sure that your OS is not located here.       
        Check that the size of the card matches the dmesg output before continuing.     

Once sure of the drive identifier, use the following command to copy your Linux image to the board, replacing the X and `<devkit>` as appropriate:
```
$ make DISK=/dev/sdX DEVKIT=<devkit> format-icicle-image 
```

When the transfer has completed, press `CTRL+C` in the HSS serial console to return to the HSS console.                 
To boot into Linux, type `boot` in the HSS console. U-Boot and Linux will use UART1. When Linux boots, log in with the username `root`. There is no password required.      

If you are using the `icicle-kit-es-amp` machine, attach to UART3 to observe its output.

Similarly, a root file system can be written to the eMMC using
```
$ make DISK=/dev/sdX DEVKIT=<DEVKIT> format-rootfs-image 
```

### Preparing an SD Card for the Icicle Kit
Insert an SD Card (16 GB or 32 GB) into the card reader of your host PC. If the SD card is auto-mounted, first unmount it manually.               
The following steps will allow you to check and unmount the card if required:

After inserting your SD card, on the host PC, use `dmesg` to check what your card's identifier is.
```
$ dmesg | egrep "sd|mmcblk"
```
The output should contain a line similar to one of the following lines:
```
[85089.431896] sd 6:0:0:2: [sdX] 31116288 512-byte logical blocks: (15.9 GB/14.8 GiB)
[51273.539768] mmcblkX: mmc0:0001 EB1QT 29.8 GiB 
```
`sdX` or `mmcblkX` is the drive identifier that should be used in the following commands, where `X` should be replaced with the specific character from the output of the previous command.           
For these examples the identifier `sdX` is used. 

#### WARNING:              
        The drive with the identifier `sda` is the default location for your operating system.        
        DO NOT pass this identifier to any of the commands listed here without being absolutely sure that your OS is not located here.       
        Check that the size of the card matches the dmesg output before continuing.     

Next check if this card is mounted:
```
$ mount | grep sdX
```
If any entries are present, then run the following. If not then skip this command:
```
$ sudo umount /dev/sdX
```
The SD card should have a GUID Partition Table (GPT) rather than a Master Boot Record (MBR) without any partitions defined.

#### Programming an Image for the First Time    
To automatically partition and format your SD card, in the top level of polarfire-soc-buildroot-sdk, type:
```
$ sudo make DISK=/dev/sdX DEVKIT=icicle-kit-esd format-icicle-image 
```

At this point, your SD card should be ready to boot Linux.         
You can remove it from your PC and insert it into the SD card slot on the Icicle kit, and then power-on the board.
Connect to UART0 (J11) for the HSS and UART1 (also J11) for U-Boot and Linux. Settings are 115200 baud, 8 data bits, 1 stop bit, no parity, and no flow control.            
When Linux boots, log in with the username `root`. There is no password required.   

If you are using the `icicle-kit-es-amp` machine, attach to UART3 to observe its output.

Similarly, a root file system can be written to the SD card using
```
$ sudo make DISK=/dev/sdX DEVKIT=<DEVKIT> format-rootfs-image 
```

### Preparing an SD Card for MPFS
Insert an SD Card (16 GB or 32 GB) into the card reader of your host PC. If the SD card is auto-mounted, first unmount it manually.               
The following steps will allow you to check and unmount the card if required:

After inserting your SD card, on the host PC, use `dmesg` to check what your card's identifier is.
```
$ dmesg | egrep "sd|mmcblk"
```
The output should contain a line similar to one of the following lines:
```
[85089.431896] sd 6:0:0:2: [sdX] 31116288 512-byte logical blocks: (15.9 GB/14.8 GiB)
[51273.539768] mmcblkX: mmc0:0001 EB1QT 29.8 GiB 
```
`sdX` or `mmcblkX` is the drive identifier that should be used in the following commands, where `X` should be replaced with the specific character from the previous command.           
For these examples the identifier `sdX` is used. 

#### WARNING:              
        The drive with the identifier `sda` is the default location for your operating system.        
        DO NOT pass this identifier to any of the commands listed here without being absolutely sure that your OS is not located here.       
        Check that the size of the card matches the dmesg output before continuing.     

Next check if this card is mounted:
```
$ mount | grep sdX
```
If any entries are present, then run the following. If not then skip this command:
```
$ sudo umount /dev/sdX
```
The SD card should have a GUID Partition Table (GPT) rather than a Master Boot Record (MBR) without any partitions defined.

#### Programming an Image for the First Time
To automatically partition and format your SD card, in the top level of polarfire-soc-buildroot-sdk, type:
```
$ sudo make DISK=/dev/sdX DEVKIT=<DEVKIT> format-boot-loader
```
At this point, your SD card should be ready to boot Linux. 
You can remove it from your PC and insert it into the SD card slot on the HiFive Unleashed board, and then power-on the DEV-KIT.    
Connect to UART1 (J7) for the fsbl, U-Boot and Linux. Settings are 115200 baud, 8 data bits, 1 stop bit, no parity, and no flow control.       
When Linux boots, log in with the username `root`. There is no password required.      
Similarly, a root file system can be written to the SD card using
```
$ sudo make DISK=/dev/sdX DEVKIT=<DEVKIT> format-rootfs-image 
```

#### Programming prebuilt images
Prebuilt images can be programmed to eMMC or SD card which already have required partition setup.
```
$ make DEVKIT=icicle-kit-es-sel4 update-icicle DISK=/dev/sdX 
```

HSS payload and initramfs binary default locations can be overwritten with `hss_uboot_payload_bin` and `vfat_image` variables.
```
$ make DEVKIT=icicle-kit-es-sel4 update-icicle DISK=/dev/sdX hss_uboot_payload_bin=/path/to/file vfat_image=/path/to/file
```

## Supported Build Hosts
This document assumes you are running on a modern Linux system. The process documented here was tested using Ubuntu 20.04/18.04 LTS.    
It should also work with other Linux distributions if the equivalent prerequisite packages are installed.        

### Prerequisite Packages
#### Ubuntu
Before starting, use the `apt` command to install prerequisite packages:
```
sudo apt install autoconf automake autotools-dev bc bison build-essential curl \
flex gawk gdisk git gperf libgmp-dev libmpc-dev libmpfr-dev libncurses-dev \
libssl-dev libtool patchutils python screen texinfo unzip zlib1g-dev \
libblkid-dev device-tree-compiler libglib2.0-dev libpixman-1-dev mtools \
linux-firmware rsync python3 libexpat1-dev wget cpio xxd dosfstools \
python3-pip libyaml-dev libelf-dev zlib1g-dev xutils-dev
```
Install the python library `kconfiglib`. Without this the Hart Software Services (HSS) will fail to build with a genconfig error.
```
sudo pip3 install kconfiglib
```

#### Centos 8
Before starting, use the `yum` command to install prerequisite packages:
```
sudo yum install autoconf bc bison curl flex gawk gdisk gperf git gmp-devel \
libmpc-devel mpfr-devel ncurses-devel openssl-devel libtool patchutils \
python2 screen texinfo unzip zlib-devel libblkid-devel dtc glib2-devel \
pixman-devel mtools linux-firmware rsync python3 expat-devel wget cpio \
vim-common dosfstools python3-pip libyaml-devel elfutils-libelf-devel \
perl-ExtUtils-MakeMaker
```
Install the python library `kconfiglib`. Without this the Hart Software Services (HSS) will fail to build with a genconfig error.
```
sudo pip3 install kconfiglib
```
You may need to run the following commands before installing the prerequisites so that the packages can be located:
```
sudo yum groups mark install "Development Tools"  -y
sudo yum install yum-utils -y
sudo yum groupinstall "Development Tools" -y
sudo yum install epel-release -y
sudo yum install dnf-plugins-core -y
sudo yum update -y
sudo yum config-manager --set-enabled powertools
```

## Known Issues
### U-Boot Error: "boot3 not defined" or "Error: Partition(s) 1, 2, 3 on /dev/sdX have been written, but we have been unable to inform the kernel of the change"
This error is caused by auto mounting of the SD/onboard eMMC, preventing the image being written correctly to the disk. To fix this, install dconf-editor and disable automounting of the SD card.

Install dconf-editor:
```
sudo apt install dconf-editor
```
Run the program:
```
dconf-editor
```
Navigate to `org/gnome/desktop/media-handling` and turn off auto mount.      
Now you should be able to run the `format-icicle-image` command without any issues.

### "Error: Could not find bootloader partition for /dev/sdX"
This problem may occur when writing to a new SD card, or after deleting all partitions using GParted or similar.    
If you encounter this problem, simply rerun the `format-icicle-image` make command and the image should be written correctly to the disk.

## Additional Reading
[Buildroot User Manual](https://buildroot.org/docs.html)    
[PolarFire SoC Yocto BSP](https://github.com/polarfire-soc/meta-polarfire-soc-yocto-bsp)    
[MPFS-DEV-KIT User Guide](doc/MPFS-DEV-KIT_user_guide.md)    
[Kernel Documentation for Linux](https://www.kernel.org/doc/html/v5.4/)    
[Asymmetric Multiprocessing Documentation](https://github.com/polarfire-soc/polarfire-soc-documentation/blob/master/asymmetric-multiprocessing/amp.md)
