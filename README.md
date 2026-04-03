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

In the SSH session, mount root filesystem of iOS 15

`mount_apfs /dev/disk1s1 /mnt1`

Then create a new apfs volume

`/sbin/newfs_apfs -A -D -o role=r -v Xystem /dev/disk0s1`

On cellular models this would be `disk1s7` and on wifi it's `disk1s6`

Now mount it: `mount_apfs /dev/disk1s(6-7) /mnt8`

Upload iPadOS 16 root filesystem to `/mnt8/fs.dmg`

After this, set `nvram auto-boot=false`

Now do `hdik /mnt8/fs.dmg`

Take note of the mount points.

Mount fs.dmg: `mount_apfs -o ro /dev/disk6s1 /mnt2`

Then copy over iOS 16 rootfs to system partition: `cp -av /mnt2/* /mnt8`

Now delete temporary fs dmg: `rm -rf /mnt8/fs.dmg`

Now send over system and app cryptexes to /mnt8. (the smallest one is the app cryptex)

Then run hdik and get mount points for those: `hdik /mnt8/cryptexos.dmg` and `hdik /mnt8/cryptexapp.dmg`

Take note of the mount points, and use `mount_apfs` and mount them as ro. Mount cryptexOS to `/mnt3` and app cryptex to `/mnt4`

Now install the cryptexes.

`rm -rf /mnt8/System/Cryptexes/OS`

`rm -rf /mnt8/System/Cryptexes/App`

`mkdir -p /mnt8/System/Cryptexes/OS`

`mkdir -p /mnt8/System/Cryptexes/App`

`cp -av /mnt3/* /mnt8/System/Cryptexes/OS/`

`cp -av /mnt4/* /mnt8/System/Cryptexes/App/`

`rm -rf /mnt8/cryptexos.dmg` 

`rm -rf /mnt8/cryptexapp.dmg`

`mv /mnt8/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld /mnt8/System/Library/Caches/com.apple.dyld`

Add iPad mini 4 specific components:

`find /mnt1 -iregex '.*j9[6-7].*' -type f -exec /bin/sh -c 'dirname="$(echo "{}" | sed -E '\''s|^/mnt1(/.+)/.+$|\1|'\'')"; filename="$(echo "{}" | sed -E '\''s|/mnt1/.+/(.+)$|\1|'\'')"; mkdir -p "/mnt8/${dirname}"; cp -an "{}" "/mnt8/${dirname}/${filename}";' \;`

Downgrade files:

`cp -a /mnt1/Library/Wallpaper /mnt8/Library` (this part makes it use iPadOS 15 wallpaper by default)

`cp -a /mnt1/Library/Audio/Plug-Ins /mnt8/Library/Audio`

Reboot out of the SSH ramdisk

Now boot iPadOS 15 rootless with palera1n. `palera1n -l -V`

Then connect to palera1n internal SSH, password is `alpine`. 

`ssh -o 'ProxyCommand=inetcat 44' -o 'UserKnownHostsFile /dev/null' -o 'StrictHostKeyChecking no' root@palera1n`

Then fix up /var (note that this does use iPadOS 15 var).

`mount_apfs /dev/disk0s1s(6-7) /cores/fs/fake`

`rm -rf /private/var/staged_system_apps`

`mv /cores/fs/fake/private/var/staged_system_apps /private/var`

`cat /private/preboot/active`

Now disable booting to iPadOS 15.

`cd /private/preboot/*/System/Library/Caches/com.apple.kernelcaches`

`mv kernelcache kernelcache.bak` (you can skip this step, though you should at least do nvram auto-boot=false)

`nvram auto-boot=false`

Now reboot.

`reboot`

Boot back into SSH ramdisk, `mount_filesystems`, then upload the `disabled.plist` from this repo into `/mnt2/db/com.apple.xpc.launchd/`

It's important that we do this, otherwise SpringBoard won't load. Some daemons will be broken anyways.

Now reboot out of the SSH ramdisk and proceed to Step 3!

Now, convert onboard blobs to im4m, make patched boot files, also patch AMFI in 16.0 kernelcache, etc.

# Step 3

Creating boot files.

There is an automatic way to do this, use the `bootcreation.sh` script in this repo instead of these, but for manual instructions follow:

Patch iOS 15 iBSS with `iBoot64Patcher`, also make sure to create img4 with the im4m from your dumped blob

Patch iOS 15 iBEC too with `iBoot64Patcher`, but set bootargs `-v wdt=-1 rd=disk1s6`, also create patched iBEC as img4 with im4m from dumped blob

Sign patched DeviceTree.im4p with im4m from your blob, set tag as rdtr

Extract `kernelcache.release.j42d` to kernel.raw

Now use `Kernel64Patcher` and patch it with these args: `./Kernel64Patcher kernel.raw kernel.patch -e -o -h`

After Kernel64Patcher, patch AMFI: `./KPlooshFinder kernel.patch kernel.patched`

Now make a patch file with `kerneldiff`, then make an img4 and apply kernel patches.

Then, make an img4 of trustcache, with rtsc tag. It can be any trustcache, as amfi is patched here.

After making the boot files, pwn device with `gaster` then boot it.

`irecovery -f iBSS.img4`

`irecovery -f iBEC.img4`

`irecovery -f DeviceTree.img4`

`irecovery -c devicetree`

`irecovery -f Trustcache.img4`

`irecovery -c firmware`

`irecovery -f kernel.img4`

`irecovery -c bootx`

Assuming you've did everything correctly, iPadOS 16 should now boot!

Note that it will use iPadOS 15 wallpaper by default, though you can download 16 wallpapers in Settings after setting the device up




