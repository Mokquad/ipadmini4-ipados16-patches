# iPad mini 4 on iPadOS 16

Install iPadOS 16 on iPad mini 4

If you can't understand this guide in full, it's not for you.

There is a very high risk of bricking your device doing this. This is at your own risk.

I WILL NOT PROVIDE ANY SUPPORT FOR THIS, AFTER THIS POINT, IT IS FOR YOU TO FIGURE OUT YOURSELF.

# Credits

[Nick Chan](https://github.com/asdfugil) - iPad 6 iPadOS 18 guide, which some of the steps are based from

# Requirements

Your iPad mini 4 must already be on iPadOS 15

If it is not on iPadOS 15 already, update it to the latest version of 15.

Download an iPad 5 16.0 beta 2 IPSW and iPad mini 4 15.8.7 IPSW

Device must already be activated (because of potential activation issues on iPadOS 16)

Tools that are used here (this guide assumes you have them)

# Step 1

Download tvOS 16.0 beta 2 kernelcache (this is the only kernel for A8 that would allow the booting of iPadOS 16)

`./pzb -g kernelcache.release.j42d https://updates.cdn-apple.com/2022SummerSeed/fullrestores/012-30801/8496544E-3794-4361-AF13-F874BF7378AC/AppleTV5,3_16.0_20J5319h_Restore.ipsw`

Then extract iPadOS 15 IPSW and iPadOS 16 IPSW

Get `ddt.py` from [SundanceInH2A](https://github.com/NyanSatan/SundanceInH2A), make sure to have the latest version of python3 installed.

Now extract iPadOS 15 DeviceTree, `j96ap` for Wi-Fi only models, `j97ap` for Cellular models.

`./img4 -i 15.x-ipsw/Firmware/all_flash/DeviceTree.j9(6-7)ap.im4p -o devicetree.raw`

Now patch it with `ddt.py` and apply DeviceTree diff

`python3 ddt.py devicetree.raw devicetree.patched devicetree.diff`

Now create an im4p with it

`./img4 -i devicetree.patched -o DeviceTree.im4p -A -T dtre` (localboot reasons?)

# Step 2

Installing the OS

Get funny SSHRD_Script fork that makes 16.0b2 SSH ramdisk (https://github.com/pwnerblu/SSHRD_Script)

`./sshrd.sh 16.0`

`./sshrd.sh boot`

`./sshrd.sh dump-blobs` (dump onboard blobs, we'll need them later)

`./sshrd.sh ssh`

In the SSH session, mount filesystems

`mount_filesystems`

Then create a new apfs volume

`/sbin/newfs_apfs -A -D -o role=r -v Xystem /dev/disk0s1`

On cellular models this would be `disk1s7` and on wifi it's `disk1s6`

Now mount it: `mount_apfs /dev/disk1s(6-7) /mnt8`

Upload iPadOS 16 root filesystem to `/mnt8/fs.dmg`

After this, unmount `/mnt8`, set `nvram auto-boot=false`, reboot

Now boot SSH ramdisk again

Mount the iOS 16 system partition again, and `hdik /mnt8/fs.dmg`

Take note of the mount points.

Mount fs.dmg: `mount_apfs -o ro /dev/disk6s1 /mnt2`

Then copy over iOS 16 rootfs to system partition: `cp -av /mnt2/* /mnt8`

Now delete temporary fs dmg: `rm -rf /mnt8/fs.dmg`

Now send over system and app cryptexes to /mnt8.

Then run hdik and get mount points for those: `hdik /mnt8/cryptexos.dmg` and `hdik /mnt8/cryptexapp.dmg`

Take note of the mount points, and use `mount_apfs` and mount them as ro. Mount cryptexOS to `/mnt3` and app cryptex to `/mnt4`

Now install the cryptexes.

`rm -rf /mnt8/System/Cryptexes/OS`

`rm -rf /mnt8/System/Cryptexes/App`

`mkdir -p /mnt8/System/Cryptexes/OS`

`mkdir -p /mnt8/System/Cryptexes/App`

`cd /mnt3`

`find . -path './System/Library/Caches/com.apple.dyld' -prune -o -exec cp -a {} /mnt8/System/Cryptexes/OS/ \;`

`cp -av /mnt4/* /mnt8/System/Cryptexes/App/`












