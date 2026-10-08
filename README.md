# iPad mini 4, iPadOS 16.0 beta 2

This repo contains some necessary patches for iPadOS 16.0 beta 2 iPad mini 4 to be at least partially functional.

THIS DOES NOT CONTAIN ANYTHING FOR THE CELLULAR MINI 4 AT THE MOMENT, ONLY THE WI-FI ONLY MODEL AS THAT IS WHAT I HAVE.

| File           | Description                                                                           |
| -------------- | ------------------------------------------------------------------------------------- |
| `pmuhax.c`     | Kernel patcher that patches the tvOS 16.0 beta 2 A8 kernel so it can use `pmu,d2207` instead of `pmu,d2186` |
| `sandboxpatcher.c` | Patches `mac_policy_ops` to return 0 to patch sandbox. Helps fix daemon crashes.            |
| `touch-kextfix.c`  | Adds the iPad mini 4 (J96) AppleMultitouchSPIJ96 codeless-kext registration to a prelinked kernelcache |

This is NOT a guide on how to install iPadOS 16.0 beta 2 on the iPad mini 4.
