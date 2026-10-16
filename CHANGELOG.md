# Changelog

## [1.0.0](https://github.com/ysya/sshelter/compare/v0.16.0...v1.0.0) (2026-10-16)


### Features

* **cli-helper:** add sshelter-cli.exe, the console program Windows terminals run to reach sshelter.exe ([a887d86](https://github.com/ysya/sshelter/commit/a887d86a96385336e836a42c62967121ab6ff9fa))
* **cli:** add sshelter connect: start SSHelter if needed, relay the terminal, follow its size and signals ([f38d471](https://github.com/ysya/sshelter/commit/f38d47116938104570475446b6d4bd208a6762f1))
* **cli:** add the terminal modes and the client side of a session for sshelter connect ([109dc87](https://github.com/ysya/sshelter/commit/109dc87f82e1748978fe6e9dc413a00a8d5fb7b3))
* **cli:** add the Windows console's modes and restores, tested on every platform ([6c74337](https://github.com/ysya/sshelter/commit/6c74337c29400fd15cf7a46a15e6a669d016786f))
* **cli:** run sshelter connect on Windows ([5257fcb](https://github.com/ysya/sshelter/commit/5257fcbe3afd977cf3df442b0a3ea5bf608a3e6b))
* **cli:** serve the console of the process as cli::terminal on Windows ([22b58cc](https://github.com/ysya/sshelter/commit/22b58cc0b1431010c72f2575ba69fe999ff31ada))
* **config:** point a host at one key by replacing its IdentityFile lines ([724d1a7](https://github.com/ysya/sshelter/commit/724d1a71ccaaec4f25fb3534088ca2e798be12f3))
* **connect:** connect on Windows through sshelter connect, by the console helper when it is installed ([6b83e7b](https://github.com/ysya/sshelter/commit/6b83e7be57e2b086f42a70062c55a6ee6d230580))
* **connect:** open sshelter connect from Connect, the palette and the tray, and drop the password autofill and the one-shot key channel ([21701e1](https://github.com/ysya/sshelter/commit/21701e1f9f9919dce31204fa5fba7e4f4353e56d))
* **hosts:** pick a key in SSHelter for IdentityFile and say SSHelter must run ([5726a8b](https://github.com/ysya/sshelter/commit/5726a8b2165e1b99a301f5cddcfed31ab23e7eb6))
* **import:** add resumable local file publication ([5bbdbe5](https://github.com/ysya/sshelter/commit/5bbdbe5ecfef1a99dcab9e49f1dc54021e5ae02b))
* **keychain:** add a host for a key from its detail ([e2356a6](https://github.com/ysya/sshelter/commit/e2356a6520ba42fa8b4e30326f8684d3f0081bf7))
* **keychain:** add a pasted key or a key file to SSHelter, moving or keeping the file ([ffc38dc](https://github.com/ysya/sshelter/commit/ffc38dc6925688afec3be56820a0c30a7181b2ef))
* **keychain:** add New key and Generate key, and remove Generate a key file ([c339b9e](https://github.com/ysya/sshelter/commit/c339b9e1b720a8f60b955f1d2d661a13dc95c949))
* **keychain:** add the Keychain's state, model and hooks ([f8d7c9b](https://github.com/ysya/sshelter/commit/f8d7c9be27eda69b3316d7e8a8a9631a4c81dd01))
* **keychain:** export a key to a host and point the host at it ([71106f4](https://github.com/ysya/sshelter/commit/71106f46be2f92b648013447268ee3d705074ca4))
* **keychain:** generate Ed25519, RSA and ECDSA keys straight into SSHelter ([d783791](https://github.com/ysya/sshelter/commit/d78379113af0a9e928c5df29dbc06cbce269d6f7))
* **keychain:** list keys that are only on this computer and say why a file can't move ([d7f1689](https://github.com/ysya/sshelter/commit/d7f16893d9bb80ee3af50e7397cfb6e133bdd03a))
* **keychain:** put the Keychain in the sidebar and remove the old Keys dialog ([284ba1f](https://github.com/ysya/sshelter/commit/284ba1f80e1e806cc8c859c3a1328727ccbeb11b))
* **keychain:** show a key's detail with its actions, and export a private key ([fc6da85](https://github.com/ysya/sshelter/commit/fc6da8537c7abcac731628f772402223b0aada7b))
* **keychain:** show keys only on this computer, when keys were made, and their passphrase ([9f79aab](https://github.com/ysya/sshelter/commit/9f79aabef4974f7b74c7b6216534d4e7d4bd65f9))
* **keys:** deploy public keys to records hosts ([f292b46](https://github.com/ysya/sshelter/commit/f292b462db23d190d7f7a4bf52fd18d782d3965a))
* **keys:** import Records private keys from selected files ([3efe604](https://github.com/ysya/sshelter/commit/3efe6046fe78750e137bd57e20854ccfee3d505a))
* **keys:** journal local and synced key material ([ed0e236](https://github.com/ysya/sshelter/commit/ed0e23629e929e6957c23f31e2ddcceab4ea748c))
* **keys:** list the hosts that use each key file and suggest Windows' OpenSSH for git ([0352633](https://github.com/ysya/sshelter/commit/0352633a6216c555d8ac8796e14b3b1923538c86))
* **mcp:** execute records commands through the session broker ([66acc1c](https://github.com/ysya/sshelter/commit/66acc1cde84fbbc888438ce7de4a2d3bbed0eb93))
* **profile:** add development destination checks ([9b31c65](https://github.com/ysya/sshelter/commit/9b31c65aaf7ccb3995569f1f050a1c95bf2c6959))
* **profile:** define development profile names and paths ([06de553](https://github.com/ysya/sshelter/commit/06de553b1f25d84a643f10bc973aca103aa7b567))
* **profile:** isolate development storage and runtime integrations ([0d269aa](https://github.com/ysya/sshelter/commit/0d269aae95fb06b5e685e587c095eb38db472847))
* promote the unified SSH workspace to 1.0 ([5247798](https://github.com/ysya/sshelter/commit/5247798db7fa20795ecdfbba6625a670225cfba7))
* **records:** add account leave and code rotation controls ([44dc0a8](https://github.com/ysya/sshelter/commit/44dc0a835e7ad9251dd58d0c9572cd1e6d6d2d38))
* **records:** add collection workspace and first-launch recovery ([7b96d83](https://github.com/ysya/sshelter/commit/7b96d837de685956881bf2cc869021e28c24f7fd))
* **records:** add explicit migration preview and recovery ([63701f8](https://github.com/ysya/sshelter/commit/63701f81a561e652bc07aa8268d5c21465313164))
* **records:** add isolated record workspace UI ([ef50a18](https://github.com/ysya/sshelter/commit/ef50a18170c3659e343978c2b25d8ea69780e394))
* **records:** add nested groups and inherited settings ([2b8ef00](https://github.com/ysya/sshelter/commit/2b8ef00f69938c1e902a768d0865bb21c514e2bf))
* **records:** unify hosts into one synced library ([76c8250](https://github.com/ysya/sshelter/commit/76c8250c23a96b73cee7022e3ae7c583ffac87b4))
* **session:** add the broker's host directory interface, a fake for its tests, and the pin store ([2f92145](https://github.com/ysya/sshelter/commit/2f92145e1afc45cd250cd898c4adc72c520d0cc6))
* **session:** add the frames and messages of the local IPC protocol ([27d876e](https://github.com/ysya/sshelter/commit/27d876ef3c60c6496ec112208f8853205a2be382))
* **session:** add the temporary directory over today's ssh_config hosts, vault keys and a pin file ([8d284b2](https://github.com/ysya/sshelter/commit/8d284b2911128bf4f3f0c0bb1479e77a746ff57b))
* **session:** confirm host keys in a window of their own ([e66120f](https://github.com/ysya/sshelter/commit/e66120f8d6e31874ff6bed000b7ae2c435971716))
* **session:** connect through host key confirmations, typed passwords and a changed key type ([950c9b6](https://github.com/ysya/sshelter/commit/950c9b652e7767b2a69195aea9eb24bb99115009))
* **session:** give the engine the broker's host key policy and an auth source over the vault, the keychain and the session's owner ([43de03b](https://github.com/ysya/sshelter/commit/43de03bc451d3a200ce7fd9164601e3131ac4bd4))
* **session:** relay a shell to its client and say how it ended ([7920b56](https://github.com/ysya/sshelter/commit/7920b567d34730df441594b05e5a144d80e58a0c))
* **session:** say how long the app waits in end_all on quit, and what a shell still being opened gets ([fce8e3f](https://github.com/ysya/sshelter/commit/fce8e3fa7d2c14b72a2864a658c3bc97fd432ff4))
* **session:** serve sessions to clients over the local IPC socket ([7a15c77](https://github.com/ysya/sshelter/commit/7a15c7776aeb42d68df462fbf56ad1f2c054ca45))
* **session:** serve the broker on a named pipe on Windows ([4d6fa45](https://github.com/ysya/sshelter/commit/4d6fa4554edf17e0a31a550a583631f3a7b56ba1))
* **session:** start the broker with the app, keep the app running while sessions are open, end them when it quits ([da5bf0a](https://github.com/ysya/sshelter/commit/da5bf0ab607a7cc3699d9f5667e48f0f2230217b))
* **ssh:** add the bounded shell output queue and the queued shell ([07bcf02](https://github.com/ysya/sshelter/commit/07bcf020d1b0018dd51b380a27a05303a833ef65))
* **ssh:** add the engine interface: types, errors and traits ([9e9c33e](https://github.com/ysya/sshelter/commit/9e9c33e7b0df422ac2a04a5bb748a2ce2a7f80bd))
* **ssh:** connect through jump hosts and keep the real cause of a chain's end ([d30a4fe](https://github.com/ysya/sshelter/commit/d30a4fe05880029515dc5e2287009eeceeb94de0))
* **ssh:** connect, check host keys and log in with vault keys through russh ([723c6b7](https://github.com/ysya/sshelter/commit/723c6b7f1d6f0a4e6428069164bcffd36e968e42))
* **ssh:** resolve and pin hosts through record snapshots ([59beff4](https://github.com/ysya/sshelter/commit/59beff4636ab1e5fbc16bc48cde48a957845bea3))
* **ssh:** run commands and PTY shells over an established connection ([ce0a2ab](https://github.com/ysya/sshelter/commit/ce0a2ab756bfe57fc00390a5bee25270252a70a1))
* **ssh:** tell the broker when a password could still get in, pass on the server's banner, and say why a shell was refused ([bfcd511](https://github.com/ysya/sshelter/commit/bfcd51188a7140a0786fc0b7bfd683b14b0a1e60))
* **sync:** activate typed record account transport ([93bba75](https://github.com/ysya/sshelter/commit/93bba75c46545ef3e2ed77f1c3e7b2aeae66d28d))
* **sync:** add bounded read-only import sources ([2f59b8c](https://github.com/ysya/sshelter/commit/2f59b8c27174951f926f219cde5ebe92499e52c5))
* **sync:** add immutable v3 record repository ([24a3561](https://github.com/ysya/sshelter/commit/24a35610c32aaa38e24f654ca49c9552fa9fbe4c))
* **sync:** add pure typed record transport merge ([3a6775f](https://github.com/ysya/sshelter/commit/3a6775f454f794fcc3ddb9aeedfcffa54cb9dd29))
* **sync:** add resumable legacy account migration ([72c32ba](https://github.com/ysya/sshelter/commit/72c32ba01e1eddc411edbdc7b12fd8c76c96f1a7))
* **sync:** add resumable record leave and rotation ([09e0a42](https://github.com/ysya/sshelter/commit/09e0a423d10d71ca3265f62d3332d5f4f8288c89))
* **sync:** add typed host and keyslot record primitives ([094b2b6](https://github.com/ysya/sshelter/commit/094b2b618fc1cb0f0fd727c92090b9b36d74a427))
* **sync:** define passive v3 state and legacy decoding ([39fd852](https://github.com/ysya/sshelter/commit/39fd85240334982b8892ac9ad55bf1aefa27d32a))
* **sync:** derive stable migration host ids ([8774bfb](https://github.com/ysya/sshelter/commit/8774bfb3242100f9cb90f6e737f1dc2adcd7a2f5))
* **sync:** land synced keys in SSHelter's vault, with a file only when the vault can't be used ([96b5d0e](https://github.com/ysya/sshelter/commit/96b5d0ebcc783a1761bf0a3064a909fbe3b621ce))
* **sync:** mark keys still kept as files and move them all into the vault ([333b32c](https://github.com/ysya/sshelter/commit/333b32cfc8f5320c81ff30e380569f0ae321c635))
* **sync:** offer keys in SSHelter's vault in the Sync key dialog ([9dd510a](https://github.com/ysya/sshelter/commit/9dd510a6984f5267273ca99ba9bf59a238425337))
* **sync:** persist active record candidates before publication ([7c17156](https://github.com/ysya/sshelter/commit/7c171568f3c42e47978afacbc8696736674e797b))
* **sync:** preview static SSH hosts without side effects ([7736cac](https://github.com/ysya/sshelter/commit/7736cacc33c24a468d223eac53a4d248917fcbe2))
* **sync:** put picked and synced keys into the vault and keep the key a vault slot had ([f189761](https://github.com/ysya/sshelter/commit/f189761b31c59fc93db73383a0a4caf425f55945))
* **sync:** wire isolated record workspace and native lifecycle ([2e26433](https://github.com/ysya/sshelter/commit/2e26433ef79cd1df64f3927f80aaf2b82a758727))
* **tray:** add stable record quick-connect ([27ea7b0](https://github.com/ysya/sshelter/commit/27ea7b03af2794ebe2b0bf82d61881db38f361f4))
* **ui:** add group browsing and settings inheritance ([f071333](https://github.com/ysya/sshelter/commit/f071333f8889f690e455c277e775e717937d588a))
* **ui:** add records MCP approval and authentication flows ([246bd56](https://github.com/ysya/sshelter/commit/246bd5677094fca25da3631878673ec3eafa38b9))
* **ui:** center the workspace on browsing and quick connect ([dd77dce](https://github.com/ysya/sshelter/commit/dd77dceeb871852a931f8023304cdcbb9122bb82))
* **ui:** make connection details width adjustable ([8688e72](https://github.com/ysya/sshelter/commit/8688e729b2588f977cbda4b3ff90ff1a7abd63ba))
* **ui:** organize settings and unify legacy surfaces ([e739770](https://github.com/ysya/sshelter/commit/e739770955c8a37e040198da1b04e8600a80a749))
* **ui:** unify library workflows and motion ([eed6881](https://github.com/ysya/sshelter/commit/eed6881db0aab51420bb45b16247df58dcd7e221))
* **vault:** add bounded read-only vault snapshots ([c78caea](https://github.com/ysya/sshelter/commit/c78caea26f331287b22f4f038c032f9aa1b486ea))
* **vault:** export a private key to a file the user picks, optionally with a passphrase ([4ff1f68](https://github.com/ysya/sshelter/commit/4ff1f68e2cd5709d55b60740ba0bc91c52134d45))
* **vault:** keep a replaced key as a retired entry instead of dropping it ([e483825](https://github.com/ysya/sshelter/commit/e483825652286f000a27537e28d3876ebe1c6a57))
* **workspace:** add reviewed sync and MCP connection setup ([c336f97](https://github.com/ysya/sshelter/commit/c336f97610e6ba7d583e930c1145558704350083))


### Bug Fixes

* **agent:** keep spawned processes from holding the agent's sockets ([c4c701e](https://github.com/ysya/sshelter/commit/c4c701ed4ca44a6f870e41b8f0bd5e0d88db17ff))
* **agent:** refresh the agent config right after a host's IdentityFile changes ([5b5192d](https://github.com/ysya/sshelter/commit/5b5192d95013941a6b38a8481ec0ac23464554f6))
* **cli-helper:** put the console's four settings back once sshelter.exe has ended, also when the installer killed it ([fa2a128](https://github.com/ysya/sshelter/commit/fa2a12879fe61707321ca30f4caaf8fdb90fe698))
* **cli:** catch SIGQUIT so Ctrl-backslash at a hidden prompt cannot kill the program with echo off ([4e3cbe4](https://github.com/ysya/sshelter/commit/4e3cbe4292b8d89cf41970fb51db6ac14d12f434))
* **cli:** clear IUCLC in raw mode on Linux, and test every flag raw mode touches ([5f44e73](https://github.com/ysya/sshelter/commit/5f44e73b942d1baf581e6c24c4d7d3ce72b659dd))
* **cli:** compile the argument conversion on Unix only, where its callers are ([2c72565](https://github.com/ysya/sshelter/commit/2c725650bbab9b28a06bf03db9c49ad2fc30dabb))
* **cli:** do not start a session whose signals cannot be taken over ([0507bef](https://github.com/ysya/sshelter/commit/0507bef09c16fc1b4c26e4d9c693ab1d01aa2342))
* **cli:** drop typeahead the stdin thread already queued when a question flushes the terminal ([30a7543](https://github.com/ysya/sshelter/commit/30a75433b0c9047a93b188c26bb5570ec5d2165c))
* **cli:** end a question's read at a change to cooked mode that keeps what was typed ([6103d3c](https://github.com/ysya/sshelter/commit/6103d3c8fd750aea0cc34b47767e77314275906c))
* **cli:** end a question's read when the session ends under it, and drop what a wake leaves ([8aff312](https://github.com/ysya/sshelter/commit/8aff3124a1b5a41e9eb9585c335397f81666eaf7))
* **cli:** end the line of a question before the reason of an end, and make a second question or opened over a question safe ([c4a0ecb](https://github.com/ysya/sshelter/commit/c4a0ecb813b595b8d4aaf10cf2d9b4f70d7364cf))
* **cli:** end the program from a watchdog when its loop does not, and stop reading a terminal that hung up ([3a8f741](https://github.com/ysya/sshelter/commit/3a8f741b841be6facf27ee74c13cdd34e58fa42b))
* **cli:** end the program when one of its own threads panics ([b856387](https://github.com/ysya/sshelter/commit/b8563879bfdb3fc4a11948cd87529c407565ff56))
* **cli:** end the session with a sentence when the broker sends a message the CLI cannot read ([a3edb87](https://github.com/ysya/sshelter/commit/a3edb872ae453104bd50b17a550a5c6acbdc3807))
* **cli:** give the Windows console xterm's line endings in raw mode only ([4c9c348](https://github.com/ysya/sshelter/commit/4c9c348a64aec239b7e3053eadc6400f7beb86ca))
* **cli:** hide what is typed at the pause, and pause only for a failure the person did not cause ([a028cb6](https://github.com/ysya/sshelter/commit/a028cb6fe514d605d2444cdc65c4d7cef4ee587c))
* **cli:** hide what is typed at the pause, and pause only for a failure the person did not cause ([7c8bfe6](https://github.com/ysya/sshelter/commit/7c8bfe63423b206e215662f1f668089a1ca28f1e))
* **cli:** keep the console marked changed when a failed take-over cannot put its output mode back ([e54269e](https://github.com/ysya/sshelter/commit/e54269e957d25aa4a5a35172125c86644a47fb24))
* **cli:** keep the reason of a connect that fails before the shell opens on screen until Enter ([800625e](https://github.com/ysya/sshelter/commit/800625e7048163b7adb12d8510f3bbd5556529a9))
* **cli:** keep the reason of a connect that fails before the shell opens on screen until Enter ([6d95825](https://github.com/ysya/sshelter/commit/6d95825613d29a4fdb5b5d57d08a6cff4c8886fb))
* **cli:** keep typed secrets out of Debug output and unwiped buffers ([5572d34](https://github.com/ysya/sshelter/commit/5572d349722f3551b4eac229e58c5cc641264ca8))
* **cli:** leave the line break after a hidden answer to the Windows console ([bc9bb8b](https://github.com/ysya/sshelter/commit/bc9bb8b6ad655d5f0980b0aa03020052d030e61e))
* **cli:** let a signal end the wait for a slow terminal at an end the session came to ([805c5ce](https://github.com/ysya/sshelter/commit/805c5cef2c019c4671473028ca2c89a8c569e86d))
* **cli:** look for a terminal before reaching or starting SSHelter ([ffa9737](https://github.com/ysya/sshelter/commit/ffa97370ba09c2c4dc1a14b670c81e151bca6ab3))
* **cli:** print every text the broker wrote through the CLI's own sanitiser ([49a11f9](https://github.com/ysya/sshelter/commit/49a11f9811f4f000bd3de723717fe4a7c1ebdfd5))
* **cli:** put the console back before a waiting control handler is let go ([97c16f2](https://github.com/ysya/sshelter/commit/97c16f2cfd5b2c38c6aa308ab44b811566933bf3))
* **cli:** put the terminal back when Ctrl-Z stops the program, and set its mode again and ask again when it continues ([1a963b3](https://github.com/ysya/sshelter/commit/1a963b3477b8c5944e9b3c907aea8941a3c71297))
* **cli:** read the program's arguments as OsStrings, so one that is not UTF-8 gets the usage ([fbb9dac](https://github.com/ysya/sshelter/commit/fbb9dac2acc088dd86fa9503632e7caeda31c4af))
* **cli:** send typeahead in frames of at most DATA_CHUNK and put the terminal back before telling the broker ([5ada932](https://github.com/ysya/sshelter/commit/5ada932d6d3b8d3e9c94d540b35cf25089f9b115))
* **cli:** show all of the shell's last output on a slow terminal before the program exits ([b1a8ffb](https://github.com/ysya/sshelter/commit/b1a8ffbbba6ee1c68bd344a488f0d92acb42e475))
* **cli:** start the reason on a line of its own when the console left a question's line open, and no blank line after Ctrl-Z ([17aca5d](https://github.com/ysya/sshelter/commit/17aca5dbbdd7fbbdd96c8a170bbca0410d3d33b3))
* **cli:** take a read of nothing for a closed terminal only when the terminal says it hung up ([26516fe](https://github.com/ysya/sshelter/commit/26516feb87cb2200feb12465f4130a93baa95842))
* **cli:** take an aborted console read for nothing, not the console gone ([9a463bf](https://github.com/ysya/sshelter/commit/9a463bf4e5c39f2e359caea55d69734d676877d9))
* **cli:** take the Windows console over only when every way out can put it back ([44e07fc](https://github.com/ysya/sshelter/commit/44e07fc9f9ebc58a36dcd8d4439e7dc9ff854a94))
* **cli:** throw away what was typed for a question when the session ends under it ([2db903a](https://github.com/ysya/sshelter/commit/2db903abf3aac2902869646b1ea17865cb8dbed7))
* **cli:** wait out a terminal write that would block instead of giving up on the terminal ([b1d5d2c](https://github.com/ysya/sshelter/commit/b1d5d2c84d976f82280cbea2ee5f06cbcaa3aa6c))
* **cli:** wipe the password of an answer after it is written ([852dbc4](https://github.com/ysya/sshelter/commit/852dbc40ac3bea3e674fb1fa569b76841ba770cc))
* **cli:** wipe typed bytes wherever the loop drops them, and read the keys without std's stdin buffer ([d43c661](https://github.com/ysya/sshelter/commit/d43c6613aae936d18e93c8a991582bb282f8b8de))
* **cli:** write to the terminal and to the broker from threads of their own, and bound the output that waits ([b53ac27](https://github.com/ysya/sshelter/commit/b53ac27a7d36e29cd7f02f85c2c64cee65d55342))
* compile connect_argv only where it is used, and stop promising the password autofill ([1e2f160](https://github.com/ysya/sshelter/commit/1e2f160998330a822ee985b0f64027418d0d957c))
* **config:** quote an IdentityFile path that has spaces ([d3298fe](https://github.com/ysya/sshelter/commit/d3298fe2498a252f5c89596bb30773ff902b5ef1))
* **config:** restore backups through managed path identities ([aba70f9](https://github.com/ysya/sshelter/commit/aba70f9933052e59bd37009289d1498dd7fee196))
* confine development legacy filesystem writers ([6232b42](https://github.com/ysya/sshelter/commit/6232b42e154ecaa3830bd7bcd7078a31f021f154))
* **connect:** run sshelter.exe itself on Windows only in a debug build, and say when a release build has no console helper ([1e587e6](https://github.com/ysya/sshelter/commit/1e587e6d99857f65d39d6cf8f4683ddc7382ce68))
* **deploy:** re-read the config after a failed IdentityFile write so the retry works ([3d59c70](https://github.com/ysya/sshelter/commit/3d59c703ad820e11a2dad987dbbd94595330b407))
* **deploy:** read the host's keys before the attach line, and offer a retry ([6f127de](https://github.com/ysya/sshelter/commit/6f127de8e9379db37571333b1d27c3bc568c51d5))
* **editor:** stop saying that ssh asks for the saved password on Windows ([f3c668d](https://github.com/ysya/sshelter/commit/f3c668de86f7d79b6aeb2ae2a0f8a70e5eefeaaf))
* **hostkey:** register the window's listener before it fetches, and ask no withdrawn question ([ecabf5d](https://github.com/ysya/sshelter/commit/ecabf5dc8be127f4aaad5d2686b5a4e3c781bfd6))
* **ipc:** connect only to a pipe the user owns ([53c8d45](https://github.com/ysya/sshelter/commit/53c8d45b56651948989f0e74a70c76d02dafc8c2))
* **keychain:** ask before New key moves a key file into SSHelter ([06377c2](https://github.com/ysya/sshelter/commit/06377c21f501e5d86aebb5845b928a2dd12addfe))
* **keychain:** check the vault's copy and the file again before a Move removes it ([387d216](https://github.com/ysya/sshelter/commit/387d216c6efabbbdba222bea02573044e4897903))
* **keychain:** don't delete a key file the loaded config can't vouch for ([6bb50d0](https://github.com/ysya/sshelter/commit/6bb50d051fbbb07ca7b0cde39f2082f7b23c9cd2))
* **keychain:** don't say a pasted key stays as a file ([a2a55dd](https://github.com/ysya/sshelter/commit/a2a55dd6c7c1ebceeca3c13ff3217378d48b9e36))
* **keychain:** keep listing this computer's keys in SSHelter without a sync account ([965a1e9](https://github.com/ysya/sshelter/commit/965a1e9fd531ad21aaee0caf2e4fd07044a91069))
* **keychain:** keep the passphrase optional in Export private key and show where a key file lives ([44b8d1a](https://github.com/ysya/sshelter/commit/44b8d1a40a16b2ee361af541168f55027efb1922))
* **keychain:** keep the user's pane when a slow New key finishes late ([e672037](https://github.com/ysya/sshelter/commit/e672037c3048032832a86f3893bcc97eff786022))
* **keychain:** keep unsaved host edits while the Keychain shows ([5643152](https://github.com/ysya/sshelter/commit/5643152c3de20f5d87ddda62988c8a281696d56b))
* **keychain:** let Delete copy remove an unused link without a sync account ([e60ffdf](https://github.com/ysya/sshelter/commit/e60ffdf5694274c071d8d545c0b98cd09d7ffc92))
* **keychain:** list keys only on this computer when the sync account's keys aren't loaded ([987a796](https://github.com/ysya/sshelter/commit/987a796f57a903fc7983f7aa61a24780c5a9e6ce))
* **keychain:** never delete a key file while something still points at it ([5d226c0](https://github.com/ysya/sshelter/commit/5d226c04f77bdce72d92a5fdd187c58245171270))
* **keychain:** point the missing key lint and the README at the Keychain ([d93df07](https://github.com/ysya/sshelter/commit/d93df07d0177bef9a0c2e72c55bd9d45bf1ec3d8))
* **keychain:** put a key lost from the vault back into its record ([d18a697](https://github.com/ysya/sshelter/commit/d18a697cbb468f8bd7b93d20ac6c73fc71e66f32))
* **keychain:** refresh slots after pointing a host at a key and share the overview mutation path ([4b8ea68](https://github.com/ysya/sshelter/commit/4b8ea686b6065dd2f6a3d3a31b103c585fa25449))
* **keychain:** refuse Move and Delete copy up front where the state can't be saved ([db9efbf](https://github.com/ysya/sshelter/commit/db9efbf1cc956100d50b9cbbfea04b53cbaa1aa5))
* **keychain:** report Move's failures even when the Keychain closes first ([2f8abf1](https://github.com/ysya/sshelter/commit/2f8abf1e1dacc898b497c8588a2663dfa8352d96))
* **keychain:** show a failed IdentityFile change with hidden characters revealed ([07642d9](https://github.com/ysya/sshelter/commit/07642d97a236497828c52800c8c2b538ada558de))
* **keychain:** show Hosts when a host is selected from anywhere ([a562ce8](https://github.com/ysya/sshelter/commit/a562ce8ca5f22babecce1fa722757d65f9bc1d9b))
* **keychain:** warn when dropped key files can't be heard ([fa65a01](https://github.com/ysya/sshelter/commit/fa65a014e7fbc72cb119dc268f88bf80f51a906d))
* **keychain:** wrap the Move confirm's path, title a failed Delete key, ignore a late Move press ([f49709c](https://github.com/ysya/sshelter/commit/f49709cfe961fa0265a0c3cd0fb9edbbfcb66034))
* **keys:** bind deployment targets and preserve CRLF keys ([85a902e](https://github.com/ysya/sshelter/commit/85a902e21bd0bb2d27efbedd6bd03bf4145c355f))
* **macos:** guard WebView startup against stalled CoreAudio ([f9ad05a](https://github.com/ysya/sshelter/commit/f9ad05afe79452f4d1deb112d06971c7b6934a48))
* **mcp:** bound the wait for mcp-spawn.lock and start without it if it can't be taken ([e867af9](https://github.com/ysya/sshelter/commit/e867af9712b8e86eed9493b1d2c80e78fe293151))
* **mcp:** bring back the window when an adapter-started SSHelter restarts ([e70f412](https://github.com/ysya/sshelter/commit/e70f412f5146441b37abc204eb6fe34a9360ab91))
* **mcp:** keep the bridge accepting after a failed accept ([edf5350](https://github.com/ysya/sshelter/commit/edf5350f5dd281d7f7c8ffa0ebffe2caccad39f9))
* **mcp:** keep the MCP host running when the AI tool ends its session ([740e2b8](https://github.com/ysya/sshelter/commit/740e2b8dbe311cde576dcdd6477d52387c0d4ed5))
* **mcp:** let a debug build run next to the installed SSHelter ([7bd24d3](https://github.com/ysya/sshelter/commit/7bd24d3e029fe41c97eb24f049d1b7ec8231cf1c))
* **mcp:** release pin waits and enforce approval deadlines ([e8b8da0](https://github.com/ysya/sshelter/commit/e8b8da06faeaa70d840a04b329015aaebd13ae8b))
* **mcp:** remove the MCP runtime file when its SSHelter exits ([415be8b](https://github.com/ysya/sshelter/commit/415be8bcd40bf9f5091593b1ba18791a2cf129fd))
* **mcp:** run one SSHelter at a time ([37ba1a9](https://github.com/ysya/sshelter/commit/37ba1a94e5c9aef93d9e87d0db67ed3fb393b573))
* **mcp:** say what to do when SSHelter doesn't answer ([a449e5f](https://github.com/ysya/sshelter/commit/a449e5fb266feadf5db13183aa1ca1f7f7d0e566))
* **mcp:** start SSHelter once when parallel calls find no bridge ([07155e0](https://github.com/ysya/sshelter/commit/07155e09ec6b2b83b6966c93b307b68c2702829d))
* **mcp:** start the MCP host in the background ([0e2ccb7](https://github.com/ysya/sshelter/commit/0e2ccb7d714be278bdec03a6d5cbe0b8f9e7d5d8))
* **paths:** reject projected children of regular files ([0d649a7](https://github.com/ysya/sshelter/commit/0d649a7c772983e3ab2dbc3395a2fa0bacab1dc8))
* **profile:** close legacy SSH isolation gaps ([f3ec385](https://github.com/ysya/sshelter/commit/f3ec3859491265f884b85f9e2d4e291404ae0642))
* **records:** add host actions and clarify sync progress ([41d730b](https://github.com/ysya/sshelter/commit/41d730b8f7f02cae0c58b1a778d77356d46facf4))
* **records:** bind group deletion to reviewed snapshot ([30c4a4c](https://github.com/ysya/sshelter/commit/30c4a4c689b86a95bb17b8cc4fae90bb3469b686))
* **records:** use authenticated key sync status ([b99ccbb](https://github.com/ysya/sshelter/commit/b99ccbba1253e4e407f336fa0b81abf12bb09e87))
* **session:** ask nothing of a client that is gone, and do not wait out the deadline of a question asked after it left ([52f56fb](https://github.com/ysya/sshelter/commit/52f56fba4cb44e0253d56d11a622335717ea972d))
* **session:** bound ssh -G with a deadline and kill the process group it started ([6b78052](https://github.com/ysya/sshelter/commit/6b78052a7cfa9e4bb03597848ea6cf185122adcd))
* **session:** build the vault key without has_passphrase, which the broker no longer has ([5f22833](https://github.com/ysya/sshelter/commit/5f22833bf7e0981dbc31423350780e2a15b685df))
* **session:** close a session's connection before its entry leaves the table ([ce3e940](https://github.com/ysya/sshelter/commit/ce3e9407b2b15107b7f7e2b04077d83b67a30e54))
* **session:** connect again with the hop's own method order after a typed password ([5223a43](https://github.com/ysya/sshelter/commit/5223a43c758843a6381e53337ed7f26439c4cab2))
* **session:** count the jump hosts of a chain, not how deeply they are nested ([eae33b1](https://github.com/ysya/sshelter/commit/eae33b1df58d7509768792c13aba6cb5c384bb87))
* **session:** count the password asked before the connect among the three a hop gets ([cde1393](https://github.com/ysya/sshelter/commit/cde139365ae54611195297f23bd2f1764e93b778))
* **session:** cut the text of an error or a disconnect to 512 characters where it is sent ([668a389](https://github.com/ysya/sshelter/commit/668a389bc4a2aa67876763c1bb07442d7fd9241d))
* **session:** date a changed host key's question from the pin it is about ([d79f744](https://github.com/ysya/sshelter/commit/d79f744a70f3d6f0d720fb3429e34ab9b20281a6))
* **session:** derive the bound on the connect's rounds from the chain and ask for a host key once per host ([4e51042](https://github.com/ysya/sshelter/commit/4e51042fffe169d95e24c1b637468352b656327f))
* **session:** do not ask the host key window about a connect whose client has gone away ([07b8a71](https://github.com/ysya/sshelter/commit/07b8a719a01824be1970a80f9ed14da38dac1287))
* **session:** do not tell a client that its session could not be started when the app is quitting ([49435d8](https://github.com/ysya/sshelter/commit/49435d80e4035fe819ce5a342a658e66a9cf0c79))
* **session:** end a connect as cancelled, and close its session, once the client has gone away ([6c6cf02](https://github.com/ysya/sshelter/commit/6c6cf024b8304c3f4855ef972b5b381249e9b9c1))
* **session:** end the connect when the person gave up a password, before any host key is asked about ([c9a4c21](https://github.com/ysya/sshelter/commit/c9a4c21a2e68ab543f063d9d06d0c5726f1a3fd1))
* **session:** forget the session and hang up even when its thread panics ([9124f9e](https://github.com/ysya/sshelter/commit/9124f9eef56ff36df3ca58eda87336470df60685))
* **session:** give a connection a time bound between hello and open_shell, not only for hello ([af0d48f](https://github.com/ysya/sshelter/commit/af0d48ff2d0f97726212b53a2bf39f653daed38e))
* **session:** give open_shell the whole bound again after hello ([e0d44d5](https://github.com/ysya/sshelter/commit/e0d44d56b8d31c88688ba7d25235ab5d3d09486f))
* **session:** honour the app ending a session, and a client leaving, before and while its shell opens ([23f55e9](https://github.com/ysya/sshelter/commit/23f55e951b5db44834049d255a34eeb14104ecc4))
* **session:** judge a host's key files by what ssh -G prints for a host that names none, not by their names ([68fd83e](https://github.com/ysya/sshelter/commit/68fd83efcaeedbeebc0698109651439b254d3ba4))
* **session:** keep connecting sessions in the broker's table so that the app sees them and tells their clients when it quits ([a5e8824](https://github.com/ysya/sshelter/commit/a5e8824619c3d37d10cf60890a00a7fbdeabfd39))
* **session:** make every text the relay frames printable in one place ([c223e59](https://github.com/ysya/sshelter/commit/c223e59905613d8a25d89c544b84b4848e93cfc7))
* **session:** make the names in the connect loop's own questions and notice printable ([a5abc82](https://github.com/ysya/sshelter/commit/a5abc82605ec18c3cb3bcb720c21711d0dd2ea05))
* **session:** make the text of a connect failure printable ([d4f054c](https://github.com/ysya/sshelter/commit/d4f054cb7266bcc3d3b3e6fd3fea72d2a3374762))
* **session:** move a decoded answer into Zeroizing where it is read, before anything can return early with it ([997a5c8](https://github.com/ysya/sshelter/commit/997a5c815864ae59880fba8cc9ff88cb74ae20a0))
* **session:** name a vault key through label in the passphrase question, and say an unreadable pin through its jump host ([a7c0ba5](https://github.com/ysya/sshelter/commit/a7c0ba5a2148c92794f7f63ebb5c11fd21c5d4dc))
* **session:** put the real (user@alias) in front of every line of a keyboard-interactive prompt ([bc8c81b](https://github.com/ysya/sshelter/commit/bc8c81bada57c8a28d3deaa247660322cbed585b))
* **session:** read a host's settings with the bounded ssh -G ([25690ca](https://github.com/ysya/sshelter/commit/25690cab31bd410792817b3a3abd8067f5ed75d6))
* **session:** read a password prompt left unanswered as abandoned authentication ([6db2b73](https://github.com/ysya/sshelter/commit/6db2b73f9c26f450f92263a7d52a072b393e2fbd))
* **session:** read the pin file's format version before the rest of it, so a newer file is not called damaged ([886da1d](https://github.com/ysya/sshelter/commit/886da1d173d7ead5ae3c4a1afd4042014268a405))
* **session:** refuse a chain that names a host twice with a sentence of its own, apart from a loop, in the ssh_config adapter and the test fake ([33ab406](https://github.com/ysya/sshelter/commit/33ab4064cad2090ee76a02d52b49f21f20f93858))
* **session:** refuse a jump that names another port or user than the saved host has, instead of resolving a variant under the same id ([7cfda05](https://github.com/ysya/sshelter/commit/7cfda05ea8aa0e32e64a7c571f80d3fa119cfc73))
* **session:** refuse a message that follows exited in the same sequence as well ([5d319a7](https://github.com/ysya/sshelter/commit/5d319a7534652d63dc5e594a19fd4abe88b5d8d9))
* **session:** replace the bidirectional controls and the line separators in text a server wrote ([152c58d](https://github.com/ysya/sshelter/commit/152c58d11d13ae005a6f207277960e4a036ec587))
* **session:** return from end_all only once every client it ended has been told ([6416e81](https://github.com/ysya/sshelter/commit/6416e811d4a502b6e1eee24bfb270a2bef503705))
* **session:** route a ProxyJump list the way OpenSSH does: only the first jump host is followed into its own jump hosts ([ad13c13](https://github.com/ysya/sshelter/commit/ad13c139aef358edc4fb224932bea45c2ce179af))
* **session:** say a lost connection as one when no shell can be opened on it, and keep the reason a clause ([6b2a325](https://github.com/ysya/sshelter/commit/6b2a325e2fd381bae3646cb1e74c544f8fb8eb08))
* **session:** say a prompt too large to send could not be shown, instead of that it was cancelled ([40aa88c](https://github.com/ysya/sshelter/commit/40aa88cb51b913a4c8ee1c8766464e056b68d979))
* **session:** say a refused or unpinnable jump host key through the jump host ([1711517](https://github.com/ysya/sshelter/commit/1711517e7f295be47894f86bf698e01b4ac3b0a4))
* **session:** send a window size to the shell under the lock that remembers it ([de163f3](https://github.com/ysya/sshelter/commit/de163f31050762ff4bc5c03c85c271e6eb0eafb7))
* **session:** show a keyboard-interactive prompt without the control characters the server put in it ([d610c78](https://github.com/ysya/sshelter/commit/d610c785982afaf4df1415b352f516fff3548c2d))
* **session:** start the broker's listener once, deciding under the status lock ([5cc1bc7](https://github.com/ysya/sshelter/commit/5cc1bc7d2f5e7af56e3830b4b294544c7433c065))
* **session:** take an ssh -G stdout that had not ended for an answer read in part, and cap what a pipe keeps ([5860056](https://github.com/ysya/sshelter/commit/58600562be3e463c65a247d7692f37a923481c42))
* **session:** tell a client whose first message cannot be used why, with the version looked at first, before closing the connection ([1152462](https://github.com/ysya/sshelter/commit/1152462c7730eccc1f2cea8c449f129ab6d09614))
* **session:** tell a client whose session could not be started that it exited, not only the error ([b4e11d0](https://github.com/ysya/sshelter/commit/b4e11d03019c9a1b7296a357446a6eef996a6081))
* **session:** treat a prompt that ran out or found nobody like a cancelled one, in the password and keyboard-interactive paths ([02c4f77](https://github.com/ysya/sshelter/commit/02c4f77c7a9c6b7584f88c77a31e31c26bf6498e))
* **session:** use the pin another connection made meanwhile instead of asking about a key never seen ([27aa8d0](https://github.com/ysya/sshelter/commit/27aa8d008230606f8ae7c3a3bf8a762c039a3ab3))
* **session:** wait the broker's QUIT_WAIT when the app quits, not a shorter time of its own ([c0a109d](https://github.com/ysya/sshelter/commit/c0a109d9cd06f68a9958f9487bb7cb5b435b613a))
* **session:** write the quit sentence and exited as one piece, and nothing after exited ([4e12ec3](https://github.com/ysya/sshelter/commit/4e12ec31217c2be924190defb8878b447f2801a5))
* **ssh:** bound every channel request and keep a shell alive past its engine ([65900bc](https://github.com/ysya/sshelter/commit/65900bcf373925e62f9e87cd328e47c34f5e5847))
* **ssh:** drop the final period of an I/O error text before it goes into a sentence ([855bf41](https://github.com/ysya/sshelter/commit/855bf415d915647320209b0367f53dcc47294d62))
* **ssh:** end a command's input so that one that reads it does not wait for the timeout ([9ddb7dc](https://github.com/ysya/sshelter/commit/9ddb7dc2f179cdf430cab4b8e157c620517d7437))
* **ssh:** end a quiet handshake or login before the keepalive interval does ([0c870d2](https://github.com/ysya/sshelter/commit/0c870d275af4a89e81be483220163f848d3be767))
* **ssh:** end a timed-out handshake for good and tell a lost login from a refused one ([8924b44](https://github.com/ysya/sshelter/commit/8924b446cbd603db16f495a9a8a561ab184d41cc))
* **ssh:** keep at most 64 KiB of a server's banner per hop ([39a42e5](https://github.com/ysya/sshelter/commit/39a42e5db929b15eeb7a5c5d2ff37af020a503b2))
* **ssh:** let a session dropped inside another runtime finish its disconnect ([1fe8142](https://github.com/ysya/sshelter/commit/1fe8142015d43d0f5b0fcb32443584b8828a5c98))
* **ssh:** merge small output chunks and announce a gap as soon as the reader catches up ([41a43f7](https://github.com/ysya/sshelter/commit/41a43f75e4f7bc247962d7a15ea4b56f84124d1d))
* **ssh:** offer the fake's RSA pin as the rsa-sha2 pair and restrict nothing for a pin the real engine cannot restrict by ([1fc30d1](https://github.com/ysya/sshelter/commit/1fc30d1a9747fdaf7d0e76744b8ca343822a9e01))
* **ssh:** preserve host trust across background sync ([995ceef](https://github.com/ysya/sshelter/commit/995ceef808925af6efe68d88a87974753bcfdb88))
* **ssh:** reject superseded fingerprint verification ([21759b7](https://github.com/ysya/sshelter/commit/21759b76801fe2be77fc196f1a651a9dfae75cd9))
* **ssh:** report a stalled write as Timeout and close the channel of a command that was not started ([7d05088](https://github.com/ysya/sshelter/commit/7d05088682dfb123a02b74077a6c0e67bec6abc8))
* **ssh:** saturate the keyboard-interactive wait derived from the connect timeout ([54f5940](https://github.com/ysya/sshelter/commit/54f59400832f3c5e5a7c7495ff850ce2eb7fa1a0))
* **ssh:** say that no login method could be tried instead of "(tried: )" ([7a55c12](https://github.com/ysya/sshelter/commit/7a55c1242b970ee0cc6deb4c311d9c429c0d0107))
* **ssh:** take the first look at a chain's end off the runtime's workers ([a9a2ffc](https://github.com/ysya/sshelter/commit/a9a2ffc2cf569ac14a1a5db7d681ef46fb12821b))
* **ssh:** tell a server with no login method from a lost connection ([931d66e](https://github.com/ysya/sshelter/commit/931d66e26e0bfdc38f4d481bf0f2188546ad701b))
* **sync:** forget a vault slot's remembered passphrase when its key changes ([ae35ab8](https://github.com/ysya/sshelter/commit/ae35ab8fa2dd4ff2bcd3f88160f317a5f700796d))
* **sync:** include libraries with retained legacy sources ([99fb2ed](https://github.com/ysya/sshelter/commit/99fb2ed7a09f0029b5417a56a7b911f4f911bbaa))
* **sync:** keep refusing U+FF9E and U+FF9F at a word start on Rust 1.99 ([31d32af](https://github.com/ysya/sshelter/commit/31d32af1ac8a5500f296d0d02e1c9522f5efbfe9))
* **sync:** keep refusing U+FF9E and U+FF9F at a word start on Rust 1.99 ([8055064](https://github.com/ysya/sshelter/commit/80550643aea632b06bf65f24a4f8de7eb249cbda))
* **sync:** keep this computer's keys maintained without a sync account ([d1e644d](https://github.com/ysya/sshelter/commit/d1e644dea46edba6eaaca184b848e5705af303ec))
* **sync:** land a reused vault key through the vault and report an unreadable vault as itself ([56e7c0d](https://github.com/ysya/sshelter/commit/56e7c0dca04b803325c266787d0e6cc7fdff0c56))
* **sync:** leave keys SSHelter's agent can't hold out of File for now and Move ([ccbfcc8](https://github.com/ysya/sshelter/commit/ccbfcc85a739100e4428662849191bfeb50189c3))
* **sync:** look after this computer's own keys at the end of every sync attempt ([f1b6a61](https://github.com/ysya/sshelter/commit/f1b6a618eaba49b88748242b8878a481dfd0cf8e))
* **sync:** move only the key slots a setup creates into SSHelter ([8094a9d](https://github.com/ysya/sshelter/commit/8094a9dfce8d4cd5483affd56a85f774b5363ee6))
* **sync:** never republish a key only on this computer to the account ([5cf2263](https://github.com/ysya/sshelter/commit/5cf226399d684d89de5e79db5b936d6348e068ab))
* **sync:** preflight development profile mutations ([6766bf1](https://github.com/ysya/sshelter/commit/6766bf13632ec5671401942aea52dde1e5d82703))
* **sync:** preflight stable key retirement destinations ([60efa85](https://github.com/ysya/sshelter/commit/60efa85bd656b2fb416098fb849f99c571c75243))
* **sync:** preserve legacy data for newer account formats ([fe55072](https://github.com/ysya/sshelter/commit/fe55072a24742fb75b47c94f41690e44c82afb96))
* **sync:** preserve relationship conflicts in v3 caches ([b4a22d5](https://github.com/ysya/sshelter/commit/b4a22d55d4b0ea623238ac8bb2fd99dca865066b))
* **sync:** preserve startup and opaque record authority ([e38a3b7](https://github.com/ysya/sshelter/commit/e38a3b760758a3573aaa22f3a0987caa01fe613d))
* **sync:** preserve typed migration compatibility gates ([a4bbe0f](https://github.com/ysya/sshelter/commit/a4bbe0f94008e6c4ee767edc923e43e9a7a978ca))
* **sync:** reject stale opaque public authority fallback ([a3dd97d](https://github.com/ysya/sshelter/commit/a3dd97dbc6543d8423ebe9ef847de73cb70b4b6c))
* **sync:** separate upload review from connection warnings ([f6bcf98](https://github.com/ysya/sshelter/commit/f6bcf98edc56f3b99591649330dc9175e7dc1464))
* **sync:** serialize legacy key material format checks ([e369d07](https://github.com/ysya/sshelter/commit/e369d073d2816f06b88892bc37d44e9db3330a1f))
* **sync:** update the agent config when a picked key falls back to a link ([096815c](https://github.com/ysya/sshelter/commit/096815c71923c5612abed8e33b1a1e903d3e5946))
* **sync:** validate effective routes before space uploads ([bcfd05d](https://github.com/ysya/sshelter/commit/bcfd05d94d1a7e54e25e8a6466709894c1b08126))
* **tray:** unminimize the window from Open SSHelter ([f402a55](https://github.com/ysya/sshelter/commit/f402a55fa763bf3077212368c7ff47eba7f3a255))
* **ui:** clarify server identity confirmation ([07e669a](https://github.com/ysya/sshelter/commit/07e669a7682b4550d006e9e3ee6e1523502be424))
* **ui:** preserve pane preferences and bound submenus ([ba4ede6](https://github.com/ysya/sshelter/commit/ba4ede60ce4ab59aaa91935034febdf95ec3bd67))
* **ui:** preserve reviewed group deletion and repair previews ([a3ce927](https://github.com/ysya/sshelter/commit/a3ce927276769d544e1e2ca749730e572a4d44bc))
* **ui:** restore records settings and improve host workflows ([68a3605](https://github.com/ysya/sshelter/commit/68a3605b41d6690bd4981cc5f82bc717432077f5))
* **ui:** say plainly that ssh still asks for the saved password on Windows ([6f47115](https://github.com/ysya/sshelter/commit/6f47115c3ebda3587c234d56484bb9c0defd20d6))
* **ui:** size popup menus to their content ([95f59a9](https://github.com/ysya/sshelter/commit/95f59a960b6f1c44f18d20efe884570c7e870c00))
* **ui:** unify neutral surfaces and scrollbar styling ([9586178](https://github.com/ysya/sshelter/commit/9586178dcc98f5a828b562d9f34b8a9da3cffa47))
* **vault:** decrypt a key a second time only when ssh-key refused its scalar's length ([a306a61](https://github.com/ysya/sshelter/commit/a306a61674f39675f6a6040254e8f53841de8de5))
* **vault:** decrypt a key a second time only when ssh-key refused its scalar's length ([70cadde](https://github.com/ysya/sshelter/commit/70cadde59320c0ea899e34bd5709ce920fc2b7be))
* **vault:** read ECDSA keys whose private scalar lost its leading zero ([85910a2](https://github.com/ysya/sshelter/commit/85910a28b9fae8ff51cc3d4b5de45f9bdabef83d))
* **vault:** read ECDSA keys whose private scalar lost its leading zero ([13bc444](https://github.com/ysya/sshelter/commit/13bc444661962978308b0ab1f6bcfbf834fccd53))
* **vault:** refuse in short_scalar what ssh-key refuses in a key with a full-length scalar ([f2e72f6](https://github.com/ysya/sshelter/commit/f2e72f673f5d8ad1e9648c7d78502b3fe4f37a78))
* **vault:** refuse in short_scalar what ssh-key refuses in a key with a full-length scalar ([3b89040](https://github.com/ysya/sshelter/commit/3b89040e3c1e21c1a7054def83ed21ce23e103b9))
* **vault:** wipe the base64 and the decoded key short_scalar holds, and keep the re-padded scalar from moving ([5eb14b2](https://github.com/ysya/sshelter/commit/5eb14b264483e888c83fc4f00a8be34d8bde4df0))
* **vault:** wipe the base64 and the decoded key short_scalar holds, and keep the re-padded scalar from moving ([4a12ed3](https://github.com/ysya/sshelter/commit/4a12ed34ed00387acd0c95965a36c2e10608a7aa))
* **vault:** write an exported key owner-only from its first byte, without a temp file ([723c244](https://github.com/ysya/sshelter/commit/723c24445273382a5dbf37e3cde2a9f91a8af577))
* **windows:** enable native exception context bindings ([e37fa9c](https://github.com/ysya/sshelter/commit/e37fa9cb7574b8f9e513177226f24820218654c9))
* **windows:** handle main window creation failures explicitly ([3d39718](https://github.com/ysya/sshelter/commit/3d39718e085bf3d7db14cc28515d713a4df22c09))
* **windows:** serialize tray startup and persist crash diagnostics ([1db5c2d](https://github.com/ysya/sshelter/commit/1db5c2dc88cc3b7c2a3629f0292d3aad888fbb3e))


### Performance Improvements

* **keys:** list keys off the main thread ([0eecc41](https://github.com/ysya/sshelter/commit/0eecc410ee14c98fb856041a16b627cebd710195))

## [0.16.0](https://github.com/ysya/sshelter/compare/v0.15.1...v0.16.0) (2026-10-01)


### Features

* **ci:** beta channel script that validates beta versions and maintains the updater-beta manifest ([88a9f48](https://github.com/ysya/sshelter/commit/88a9f480f6c617d45900971a81af6ed84b8ce021))
* **relay:** zero-knowledge sync relay on Cloudflare Durable Objects ([c346f83](https://github.com/ysya/sshelter/commit/c346f83fe11a9efdd5b90b5af8d2079b26cd54b4))
* **sync:** background engine with transactional apply, save-time planning and lifecycle mutex ([44a17ff](https://github.com/ysya/sshelter/commit/44a17ff6254e70ceb705a053143f471e46ce95b0))
* **sync:** detect local host block changes with per-block change times ([26390a4](https://github.com/ysya/sshelter/commit/26390a43bfae3a241d670b97fa7c5ac86f2b9315))
* **sync:** expose first_sync_pending; the wizard moves only visible hosts and refetches after failed writes ([c6cf129](https://github.com/ysya/sshelter/commit/c6cf1299d7aba1b277121ea955b9f05fe91f64fd))
* **sync:** frontend hooks, event wiring and migration helpers ([e631b7b](https://github.com/ysya/sshelter/commit/e631b7b638c9748ca0382070987833cd4a4316d7))
* **sync:** let release builds ship without a built-in relay and ask for one in Settings → Sync ([29cd804](https://github.com/ysya/sshelter/commit/29cd804bcfec3befd64dcf7e2b52e683c5f3a54c))
* **sync:** managed hosts file block operations ([b97870f](https://github.com/ysya/sshelter/commit/b97870f2a1e02ea5cc1e58cafbf38fdcde1cf37c))
* **sync:** migrate hosts into the synced file, detect and resolve shadowed aliases by file ([432fe05](https://github.com/ysya/sshelter/commit/432fe055c191b54afb7a25b754d3422798bbd2c0))
* **sync:** migration wizard with file-addressed shadowed alias handling ([f3f3da8](https://github.com/ysya/sshelter/commit/f3f3da8ceea13802bfe9052ebd6570f3e5d206c0))
* **sync:** mnemonic, key derivation and record encryption ([97aa368](https://github.com/ysya/sshelter/commit/97aa368984435d82c11e8351f3b01727ef585b7f))
* **sync:** persist local sync state and keep the mnemonic in the keychain ([e002dc0](https://github.com/ysya/sshelter/commit/e002dc0af9b23ba869ce9241285f7579c82a13c7))
* **sync:** plan/pull-merge/push round with sealed retention and batched uploads ([5f6354b](https://github.com/ysya/sshelter/commit/5f6354b345e9a98fb9e360ad28f30e1291f960a8))
* **sync:** record model, wire envelope and last-writer-wins merge ([6e51d67](https://github.com/ysya/sshelter/commit/6e51d672b3e2fc9e748c000209e9a6000e926d4b))
* **sync:** relay HTTP client with conflict-aware push ([2783365](https://github.com/ysya/sshelter/commit/27833659b9c5856b33c365615ee1a6242d811e79))
* **sync:** settings pane to create, join, inspect and leave a sync chain ([df511a4](https://github.com/ysya/sshelter/commit/df511a48d72fad6a11e3770703fe1ca90a19e7f0))
* **updater:** backend commands to check and install from the Beta update channel ([a653bf7](https://github.com/ysya/sshelter/commit/a653bf777fb2743efff119aeaec355a5cd221624))
* **updater:** Stable/Beta update channel setting and mark sync as beta ([906dff0](https://github.com/ysya/sshelter/commit/906dff0aa821405b2c10ce19b45bb6e34c652fc6))


### Bug Fixes

* **ci:** enforce the exact beta version format and harden the beta channel script ([6a82bea](https://github.com/ysya/sshelter/commit/6a82bea316f07e33c68f23408db04cbbe7d54022))
* **ci:** enforce Windows MSI version limits on betas and clarify republishing ([62fbb16](https://github.com/ysya/sshelter/commit/62fbb16636353a09aad57daf87eedebe63704390))
* **ci:** make build-platform refuse beta tags before building anything ([a6de115](https://github.com/ysya/sshelter/commit/a6de1150a094f63e331256f2c2c7500460c6d2cc))
* **ci:** refresh the Beta manifest when a version is rebuilt and validate it before promoting ([e6f622e](https://github.com/ysya/sshelter/commit/e6f622e806fe50d52c85feaf4e024588b4aa92fa))
* **ci:** refuse existing beta tags, keep betas prerelease and reject leading zeros ([ff9f82b](https://github.com/ysya/sshelter/commit/ff9f82b291cd2d4e80950dc54eb11cf89cd2ee94))
* **ci:** refuse to publish a beta when the tag check cannot reach origin ([e9e1aca](https://github.com/ysya/sshelter/commit/e9e1acad85b50b807e467a01236503a7fdc35a63))
* **sync:** drop a stale ts-expect-error and cover lone ? wildcards ([4c4eeee](https://github.com/ysya/sshelter/commit/4c4eeeebd3a3cb317f2fd8165e4e64969ad0d46e))
* **sync:** fall back to the local relay when the injected relay URL is empty ([5d3911e](https://github.com/ysya/sshelter/commit/5d3911ec2ff43438814986ff629ce59bb02bb927))
* **sync:** keep synced names out of the wizard, wait for the first sync and show sync errors ([35de116](https://github.com/ysya/sshelter/commit/35de11607bcf096977252c22983e17bc3e80a626))
* **sync:** keep the leave dialog open until the request settles ([ed67453](https://github.com/ysya/sshelter/commit/ed67453590e16c62a5b133d241905c1743f733b1))
* **sync:** keep unpushed edits when restoring the synced file and repair a rolled-back relay ([e6a1945](https://github.com/ysya/sshelter/commit/e6a1945c1d7983ae0709d824a7ad5586ff7b3b17))
* **sync:** list failed host moves and distinguish loading from empty in the migration wizard ([f95f451](https://github.com/ysya/sshelter/commit/f95f4518c94b7b5e44a57eb863f60e4f976ad8c5))
* **sync:** one engine per OS user, bounded conflict retries and safer sync rounds ([1baf929](https://github.com/ysya/sshelter/commit/1baf9297e4c80aa88a4b7add5b10bfeb1fd7e1fe))
* **sync:** quiet startup before the config loads, restore a vanished synced file from the chain and harden state and keychain errors ([94e788d](https://github.com/ysya/sshelter/commit/94e788ddb7606fbd0fbb4385ee5f3bf240b5b6a2))
* **sync:** refuse moves that share any synced name or run without the engine, reload after a failed shadow fix ([cdbf943](https://github.com/ysya/sshelter/commit/cdbf943589ace707229aa997ab0f0282adebb83c))
* **sync:** refuse moves that would duplicate a synced alias and reload after a failed move ([657e161](https://github.com/ysya/sshelter/commit/657e1615b0a5e6bb31772a820ba123160960cf0b))
* **sync:** retry a held engine lock briefly and wake the engine after every config load ([3e4783f](https://github.com/ysya/sshelter/commit/3e4783f26407d1fc48e395ec665ee53ad8d49039))
* **sync:** stop a host migration batch at the first failed write and reload from disk ([c263572](https://github.com/ysya/sshelter/commit/c2635728314cdc9cc1009f99f50cbe84aab25270))
* **sync:** surface engine doc reloads, keep unreadable state files and emit outside the lifecycle lock ([0daa74a](https://github.com/ysya/sshelter/commit/0daa74a6ac97932349d0b1d50f52996e01bad9bb))
* **sync:** treat unreadable metadata as an error, never as a missing synced file or state ([305f0a9](https://github.com/ysya/sshelter/commit/305f0a917e153fa33416df2b1fb9fcdb65b02e65))
* **sync:** wake the engine only when a config load changes the synced file, report baseline conflicts, clarify secondary-name refusals ([2661b13](https://github.com/ysya/sshelter/commit/2661b13b26121f5ef0fe983726929f1a5d448db0))
* **updater:** ignore stale channel results and retire the update prompt on any channel change ([ca66e3a](https://github.com/ysya/sshelter/commit/ca66e3ad48291be2b694c10fd5fbc5444cbfe71f))

## [0.15.1](https://github.com/ysya/sshelter/compare/v0.15.0...v0.15.1) (2026-09-01)


### Bug Fixes

* **clipboard:** use native clipboard on Windows ([1052b21](https://github.com/ysya/sshelter/commit/1052b21f4e559366c68dfc5a6e1076f72f282155))

## [0.15.0](https://github.com/ysya/sshelter/compare/v0.14.0...v0.15.0) (2026-08-31)


### Features

* **connect:** auto-fill saved passwords when connecting ([8cc2542](https://github.com/ysya/sshelter/commit/8cc25426b248e8a2408808894ad0508e276835bc))


### Bug Fixes

* **deploy:** make in-app key deploy work on Windows ([2b1319e](https://github.com/ysya/sshelter/commit/2b1319e16c94354be69bf3b3ea9837ac77762df5))

## [0.14.0](https://github.com/ysya/sshelter/compare/v0.13.0...v0.14.0) (2026-08-24)


### Features

* **hosts:** add SSH name copy and fix Windows commands ([65f65c9](https://github.com/ysya/sshelter/commit/65f65c92eae3b807b8f8a5d23c619ca674ecbb5f))

## [0.13.0](https://github.com/ysya/sshelter/compare/v0.12.0...v0.13.0) (2026-08-14)


### Features

* **keys:** hint how to enable the Windows ssh-agent service ([122b0a3](https://github.com/ysya/sshelter/commit/122b0a3c1f5d762a4844abd5fb48120ac37220a1))
* **mcp:** add UI-controlled SSH access ([963467e](https://github.com/ysya/sshelter/commit/963467e5b5d26b8d9d78ea6e56a27e1ca14f7836))

## [0.12.0](https://github.com/ysya/sshelter/compare/v0.11.0...v0.12.0) (2026-08-14)


### Features

* **windows:** build Windows installers and launch wt/cmd terminals ([455fa6b](https://github.com/ysya/sshelter/commit/455fa6ba61b6a38479a0e4e8f5e17ff20f8c3d37))

## [0.11.0](https://github.com/ysya/sshelter/compare/v0.10.0...v0.11.0) (2026-08-13)


### Features

* **config:** new-config-file dialog with live include preview ([9c3ac32](https://github.com/ysya/sshelter/commit/9c3ac32b1b58e87f70f2b3ce9dffae42004d25c0))
* **config:** plan and create included config files ([f1fe215](https://github.com/ysya/sshelter/commit/f1fe215a8d16d4b49e8fcef3a3b55cbad4a17561))
* **host-list:** create a new config file from every file picker ([b3668d0](https://github.com/ysya/sshelter/commit/b3668d0df7a17fd8e2ad62014ae1d64a927dba4d))

## [0.10.0](https://github.com/ysya/sshelter/compare/v0.9.0...v0.10.0) (2026-08-13)


### Features

* **host-list:** drag a host onto another file group to move it ([453593f](https://github.com/ysya/sshelter/commit/453593f268643e1de4219e58fc1f2082defa4676))
* **host-list:** hover actions menu with move and remove ([efb67e4](https://github.com/ysya/sshelter/commit/efb67e48fd620d864669d66be3513274ad0968ee))
* **host-list:** multi-select with batch move, tag and remove ([c8e375a](https://github.com/ysya/sshelter/commit/c8e375a7cddb8153bda3d9c33e67d22c0109d01f))

## [0.9.0](https://github.com/ysya/sshelter/compare/v0.8.0...v0.9.0) (2026-08-13)


### Features

* **host-list:** add #tag [@user](https://github.com/user) search prefixes ([9e26e08](https://github.com/ysya/sshelter/commit/9e26e083f09243a83e539a116d22acfd10dfbfa2))
* **host-list:** group hosts by file or by tag ([4bc643b](https://github.com/ysya/sshelter/commit/4bc643b3ba6f9344e6e509826fc88688e574632c))
* **host-list:** show tag chips on host rows ([9c7b905](https://github.com/ysya/sshelter/commit/9c7b905a3fba7867087fc77e8fae0f1262d76e36))
* **palette:** surface recent connections first ([daae0d2](https://github.com/ysya/sshelter/commit/daae0d297a3dd5f8a068ff16c51ab860e80fb87b))


### Bug Fixes

* **host-editor:** demote deploy button to the menu once a key is configured ([29df22f](https://github.com/ysya/sshelter/commit/29df22f7e95b7fad509538bd08144e94cafff8d6))

## [0.8.0](https://github.com/ysya/sshelter/compare/v0.7.0...v0.8.0) (2026-08-13)


### Features

* **deploy:** add editor, palette, hygiene and keys-dialog entry points ([b73501e](https://github.com/ysya/sshelter/commit/b73501e0b218cb5bccd870ae8f392f965b7c4677))
* **deploy:** add identity-file write-back decision helpers ([c690d74](https://github.com/ysya/sshelter/commit/c690d7450e452535e2443e5dad2e3792d9471e2a))
* **deploy:** write IdentityFile back after a successful deploy ([7c3169f](https://github.com/ysya/sshelter/commit/7c3169fb7c3248e605ceb9b922771c88f50fdca1))
* **host-editor:** pick IdentityFile from detected keys or a file dialog ([e939e1a](https://github.com/ysya/sshelter/commit/e939e1a24b86126678d5edff69ae141abd291d14))


### Bug Fixes

* **ui:** disable autocorrect and autocapitalize on all text inputs ([d806a66](https://github.com/ysya/sshelter/commit/d806a66ba7afcd59a1705df1f995ad493ec8f502))

## [0.7.0](https://github.com/ysya/sshelter/compare/v0.6.1...v0.7.0) (2026-08-13)


### Features

* **askpass:** add SSH_ASKPASS helper mode with prompt whitelist ([e413437](https://github.com/ysya/sshelter/commit/e413437095fcb199c2d5517e229fc242d0cfd2e0))
* **askpass:** dispatch to helper mode before Tauri init ([be79556](https://github.com/ysya/sshelter/commit/be79556b1ff7c295766123fa477fdcd8c7c90d54))
* **deploy:** add deploy/precheck/secrets Tauri commands ([1b1b449](https://github.com/ysya/sshelter/commit/1b1b4491f09c6f26de1491b92bc817bf8d72052e))
* **deploy:** add host key precheck against known_hosts ([dbd93c0](https://github.com/ysya/sshelter/commit/dbd93c0b4bf7633281678dad90d1b3e4e6a21cb6))
* **deploy:** add in-app key deployment dialog ([b3c3780](https://github.com/ysya/sshelter/commit/b3c3780a63944832f5a00e69fb2ffad32b70520d))
* **deploy:** add pure argv builder, remote script and outcome classifier ([a343133](https://github.com/ysya/sshelter/commit/a343133f5e57d6b416d123c681744a44db4de36e))
* **deploy:** warn about old OpenSSH and password-blocking config ([94c8b19](https://github.com/ysya/sshelter/commit/94c8b1981de7d575fa2c7550b4a0214d71203744))
* **host-editor:** manage the host password stored in the OS keychain ([79f70fd](https://github.com/ysya/sshelter/commit/79f70fdd0c74817179c92b84506ce70594892542))
* **host-list:** right-click a host to deploy a key ([777fe89](https://github.com/ysya/sshelter/commit/777fe89d99b2968278b6bc6e232eb86f6683ea53))
* **queries:** add deploy and host-password hooks ([d6a89a9](https://github.com/ysya/sshelter/commit/d6a89a9ba8ffab921ef7715d51c84814134e1eed))
* **secrets:** add OS keychain wrapper for per-host passwords ([be59a76](https://github.com/ysya/sshelter/commit/be59a76211a2c456fed964edde808c784f8ef3a5))


### Bug Fixes

* **askpass:** anchor prompt whitelist to real OpenSSH client behavior ([325b34c](https://github.com/ysya/sshelter/commit/325b34ce49810ad6cf3ba54e4dd4f749c141fd6e))
* **askpass:** correct module doc and use lossy argv decoding ([e1a3c68](https://github.com/ysya/sshelter/commit/e1a3c683729249182c093aed44bacf75a22dd4cf))
* **deploy-ui:** trust the host key by confirmed fingerprint, not key line ([d0ee77d](https://github.com/ysya/sshelter/commit/d0ee77d28aac33e279a2268652378752c03b430b))
* **deploy:** close config/timeout/keychain gaps in the deploy commands ([a075bbd](https://github.com/ysya/sshelter/commit/a075bbdb81d51166d3d2ea41f2159d9fce45aeae))
* **deploy:** guard authorized_keys corruption and misclassified auth failures ([aac2fc9](https://github.com/ysya/sshelter/commit/aac2fc9e228c37a6a3b893a401ecad192c146c33))
* **deploy:** parse known_hosts markers so CA-trusted and revoked hosts are handled correctly ([646ac75](https://github.com/ysya/sshelter/commit/646ac75f278335787b78a620de8e4a11d9dbe1e1))
* **secrets:** trust any keyring error as unavailable, guard test cleanup ([5f1e44a](https://github.com/ysya/sshelter/commit/5f1e44a4f264614ed4725c3b0f267871d678e66a))

## [0.6.1](https://github.com/ysya/sshelter/compare/v0.6.0...v0.6.1) (2026-06-19)


### Bug Fixes

* **host-list:** show the Defaults group at the top of each file section ([022087a](https://github.com/ysya/sshelter/commit/022087a90dd58c55e1c72338e5229e472d08f9c6))

## [0.6.0](https://github.com/ysya/sshelter/compare/v0.5.1...v0.6.0) (2026-06-19)


### Features

* **host-list:** add target-file resolver for right-click add-host ([3934ab1](https://github.com/ysya/sshelter/commit/3934ab1d50f41658c75bcedc37aa41269bb45dbd))
* **host-list:** right-click file headers to add a host, view, or rename ([b809e95](https://github.com/ysya/sshelter/commit/b809e95ddf5bcc81eee4d984ee46ea920777e036))
* **host-list:** seed AddHostDialog target from right-click file ([c71a7a7](https://github.com/ysya/sshelter/commit/c71a7a75c2fa41bf2841fd73a6e479577af2e2c1))
* **host-list:** track right-click add-host target file in ui store ([33288f2](https://github.com/ysya/sshelter/commit/33288f2aa0821a2d8311a2cab5a960a33cbe6788))
* **ui:** add context-menu primitive ([80155e0](https://github.com/ysya/sshelter/commit/80155e03ac7d3061c285b4fe6144c6d4ae8684fc))

## [0.5.1](https://github.com/ysya/sshelter/compare/v0.5.0...v0.5.1) (2026-06-12)


### Bug Fixes

* **ui:** keep toasts clickable above modal dialogs ([cf668fd](https://github.com/ysya/sshelter/commit/cf668fddba13bbb787b61384c8fb98a2fe29ff88))
* **updater:** keep checking for updates while the app runs ([2b0a1ab](https://github.com/ysya/sshelter/commit/2b0a1aba5990e1d7a8ba7fdc1ea8ea598e8b1fa9))

## [0.5.0](https://github.com/ysya/sshelter/compare/v0.4.0...v0.5.0) (2026-06-11)


### Features

* **app:** launch-at-login, global hotkey, settings export/import, ⌘F/⌘N ([636144b](https://github.com/ysya/sshelter/commit/636144b7dfec191bc515ff7b7db0776235ce86b0))
* **hosts:** move/duplicate host across files, per-host terminal override, raw file viewer ([4eb8e52](https://github.com/ysya/sshelter/commit/4eb8e52751db1dc8a29733f1497b4cd4b162801c))
* **keys:** SSH key management — list/fingerprints/agent status, generate ed25519, copy pubkey, ssh-copy-id deploy via terminal ([c54f1ab](https://github.com/ysya/sshelter/commit/c54f1ab1038a8154dca0ab2c3cc3f869d09b32b7))
* **known-hosts:** known_hosts viewer — search + safe entry removal (lossless, backed up) ([0130f51](https://github.com/ysya/sshelter/commit/0130f510fbddd2f9bd375a914cef7191fbc63a7d))
* **ui:** drag-to-reorder hosts within a config file ([2226433](https://github.com/ysya/sshelter/commit/2226433cf3cba13036fe7df03a76c23f5799820e))
* **ui:** user-adjustable text size (Settings &gt; Appearance, scales the rem-based UI) ([09b9d2a](https://github.com/ysya/sshelter/commit/09b9d2ab0e316399af4826c18f0f4a5d307b3d86))


### Bug Fixes

* **config:** address option toggles by occurrence index (same-keyword pairs hit the wrong line) ([bbbf10f](https://github.com/ysya/sshelter/commit/bbbf10f96c5506418c59881504ffd274976cf41d))
* **ui:** overlay buttons centered with translate (-translate-y-1/2) lost ([4eb8e52](https://github.com/ysya/sshelter/commit/4eb8e52751db1dc8a29733f1497b4cd4b162801c))

## [0.4.0](https://github.com/ysya/sshelter/compare/v0.3.0...v0.4.0) (2026-06-11)


### ⚠ BREAKING CHANGES

* **config:** existing next-to-file .bak snapshots are moved into the new backups root on first load; restore only accepts backups inside the new location.

### Features

* **config:** rename host — lossless Host-line pattern editing from the editor header ([6ea2e1a](https://github.com/ysya/sshelter/commit/6ea2e1a979cb0e482cbde85ea99b635fff0ad4da))
* **ui:** sidebar v2 — file scope filter, compact rows, sticky headers, wildcard defaults footer, persisted nav state ([0e7cb97](https://github.com/ysya/sshelter/commit/0e7cb97b00d0430dae6a19ea1ba68812d0f05414))
* **ui:** user-defined display aliases for config file groups (double-click to rename) ([b450afc](https://github.com/ysya/sshelter/commit/b450afce1a5c1651781a3a438ee20ce56e807995))


### Bug Fixes

* **config:** relocate backups out of ssh-visible dirs (glob Includes were loading .bak files) ([c7c4707](https://github.com/ysya/sshelter/commit/c7c47078a24c427bfb12bfe5f54b70c4bb63e706))
* **ui:** label colliding config files by their distinctive ancestor (orbstack, not ssh/config) ([0c236ac](https://github.com/ysya/sshelter/commit/0c236ac891a94332044ad5f3ef4a97d551c76ff9))

## [0.3.0](https://github.com/ysya/sshelter/compare/v0.2.0...v0.3.0) (2026-06-10)


### Features

* **app:** auto-update via tauri-plugin-updater ([10f096b](https://github.com/ysya/sshelter/commit/10f096ba5f193d2ade835cb6ab8dbb51fa9851a9))

## 0.2.0 (2026-06-10)


### Features

* add app_platform smoke command and wire error/fsutil modules ([55b35a2](https://github.com/ysya/sshelter/commit/55b35a2e26d0ca40f42a5fbf9e90129694ee95de))
* add AppError unified command error type ([af03563](https://github.com/ysya/sshelter/commit/af03563bcd9af9692e4b9bd53fb69b2f44114d6d))
* **config:** app state + config_* Tauri commands + safe write path ([5647071](https://github.com/ysya/sshelter/commit/5647071468752d17298580d52da12c9417b16fb7))
* **config:** backup history listing + safe restore ([26cc242](https://github.com/ysya/sshelter/commit/26cc242d88a8a17153850232e0d0a315a4fec071))
* **config:** CST edit operations (set/add/remove/toggle/reorder/group) ([a4a5099](https://github.com/ysya/sshelter/commit/a4a5099a5d46b8fd35d42a0a0eb387201e6f4edf))
* **config:** CST model + quote-aware single-line lexer ([fa67dec](https://github.com/ysya/sshelter/commit/fa67dec2bce93f63bcfc9a147200f94fbe13859c))
* **config:** intelligence module — effective-config (ssh -G), linter, ProxyJump chain, key-hygiene ([3a70ba8](https://github.com/ysya/sshelter/commit/3a70ba8ba946ffeb9e12e0fa81ca5bd13dfe1c96))
* **config:** lossless parser + serializer with golden round-trip corpus ([de4b150](https://github.com/ysya/sshelter/commit/de4b150f51b52cffc1ba219f602bbbbc63e96346))
* **config:** multi-file Include loading + host DTOs ([2d196b6](https://github.com/ysya/sshelter/commit/2d196b6fe68e9878f538ee936391343c31673948))
* **connect:** terminal launcher with per-emulator argv + alias validation ([05f10f1](https://github.com/ysya/sshelter/commit/05f10f110b949328d8f1ab58a894b7f1e2e0d3b2))
* **core:** settings backend — lint rule ids, backup retention, tray toggle, close-to-tray, iTerm2 new-tab ([c92ed27](https://github.com/ysya/sshelter/commit/c92ed27ac5a073230f84580afe1ae70990cb9f09))
* **discover:** known_hosts + Tailscale host discovery ([c861d81](https://github.com/ysya/sshelter/commit/c861d81a664dd6994c5c3d9092719c138aad6139))
* **error:** add AppError::Parse variant ([7136393](https://github.com/ysya/sshelter/commit/7136393551de59c48b60a3bb32603fc5c1ec638e))
* establish ts-rs Rust-&gt;TS type bridge (Fingerprint) ([9d36ce3](https://github.com/ysya/sshelter/commit/9d36ce3be6e98f17a097fb76ea3ee5f57c99b479))
* **fsutil:** fsync parent dir after rename; document symlink/perms semantics ([43db87b](https://github.com/ysya/sshelter/commit/43db87b8ddb0129b7a0885ee145a9509b3740c0a))
* **fsutil:** safe file IO — atomic write, perms, backup, drift detection ([95d273b](https://github.com/ysya/sshelter/commit/95d273bf432ebcd994275fdc93dbc4820df246ec))
* **tray:** menubar quick-connect menu rebuilt on config load ([bae8a6e](https://github.com/ysya/sshelter/commit/bae8a6ea38430ff87e51378c7afc7b0e4754e8fb))
* **ui:** center the host editor at a comfortable column width (System Settings style) ([e04ddd4](https://github.com/ysya/sshelter/commit/e04ddd450b3b41d8e73bbbabca3f3d149011224b))
* **ui:** collapsible sidebar groups + disambiguate duplicate group labels (shortest-unique path) ([36ec195](https://github.com/ysya/sshelter/commit/36ec195d565be69019988143286eb6fa5625c068))
* **ui:** command palette (⌘K) with connect/edit + terminal picker + per-row connect ([7d7ad65](https://github.com/ysya/sshelter/commit/7d7ad65aa8f6802ac19b32f7caeef29bbf2dd169))
* **ui:** config editor data layer, field-diff logic, app shell + host list ([ef06e51](https://github.com/ysya/sshelter/commit/ef06e51f40a69a416fda97ee00cd4152bc3aac52))
* **ui:** config intelligence panels + lint/discover/history dialogs ([17b09d9](https://github.com/ysya/sshelter/commit/17b09d9f1304614ac4b32dc8d8a357b1158693a4))
* **ui:** host editor, add/remove host, group/tags, drift banner ([4713c29](https://github.com/ysya/sshelter/commit/4713c2900dc8f9b373131456e701d5dbc0686f30))
* **ui:** native instrument-panel redesign — stacked editor, system fonts (mono for values), graphite + system-blue, source-list, refined chrome ([ed87420](https://github.com/ysya/sshelter/commit/ed87420d0b15a0446567aa86cc17a97755ec9f12))
* **ui:** native macOS desktop shell — fixed scroll regions, overlay titlebar, compact density, settings-style editor ([3cb1974](https://github.com/ysya/sshelter/commit/3cb197406776d85f68bffa097e66b3b3a140c62d))
* **ui:** refined terminal-shelter redesign + dark mode ([d230b9e](https://github.com/ysya/sshelter/commit/d230b9e18b751cc103461d81064c3e61fc2f3c96))
* **ui:** Settings sheet (⌘,) — move theme + default terminal out of the toolbar ([efbc506](https://github.com/ysya/sshelter/commit/efbc50623af52022c53476b15a02a34d8eb7807f))
* **ui:** sidebar Settings window — tray, close-to-tray, new-tab connect, config path, backup retention, discovery/drift/lint controls ([1697c82](https://github.com/ysya/sshelter/commit/1697c82eefcc7cb52bd7fe14c4329c471d40cdb8))
* **ui:** toolbar reload-from-disk button (manual refresh after external edits) ([30c3575](https://github.com/ysya/sshelter/commit/30c3575351c0c8f56ca335b1544849842249f207))
* **ui:** two-pane host editor — live ssh_config preview fills wide windows, stacks when narrow ([a5c76c3](https://github.com/ysya/sshelter/commit/a5c76c3dbfaf9a39f17c087b215bf5bb07b8f81d))
* wire TanStack Query + Zustand + app_platform IPC smoke ([29a8fb9](https://github.com/ysya/sshelter/commit/29a8fb947d36560938422e6c0c643724157ffc0d))


### Bug Fixes

* **config:** clamp backup retention to &gt;=1 (0 would prune the fresh backup) ([231b874](https://github.com/ysya/sshelter/commit/231b874cea7a6e3b2158c9ba7de327f4264d7b74))
* **config:** lint matches secondary host aliases, skips disabled directives + ProxyJump none; chain handles cross-host cycles ([5f66f19](https://github.com/ysya/sshelter/commit/5f66f19e97dbd11dcb4742c6a447d27ae512a590))
* **config:** preserve trailing whitespace in lexer split via trailing_ws field ([bfd5f1f](https://github.com/ysya/sshelter/commit/bfd5f1ff8f6a3bc71302dd1d315e788fa33ca33b))
* **config:** refuse to overwrite externally-changed files (drift conflict guard) ([235cf20](https://github.com/ysya/sshelter/commit/235cf20514f6abf090d233cdedd05c8f70c64c9d))
* **config:** skip unreadable Include files instead of aborting whole load ([f5510b5](https://github.com/ysya/sshelter/commit/f5510b585d4fc75390b2c483b64a576a7efc1183))
* **config:** strip newlines from values, insert new fields before trailing blank, doc host-disable asymmetry ([d602570](https://github.com/ysya/sshelter/commit/d602570902893da6cbfae56bcdb68a84c01df0f5))
* **connect:** reject leading-dash aliases (ssh argument-injection / -F config RCE) ([c58c733](https://github.com/ysya/sshelter/commit/c58c733903a8d46ef18039a1b79354de93796c54))
* **ui:** bump root font-size 13px→15px so body text lands at the intended ~13px (was rendering too small) ([b618d4c](https://github.com/ysya/sshelter/commit/b618d4c62346525b002bf4c5f0f9c68157d2d209))
* **ui:** hide number-input spinner steppers (type the value directly) ([482812c](https://github.com/ysya/sshelter/commit/482812c0f1b3e1364dd2dd24dfcb0197bdc87dd5))
* **ui:** host rows show resolved user@hostname as a distinct subtitle (no more duplicated alias) ([52c1292](https://github.com/ysya/sshelter/commit/52c129237454fb36a2685e63cffa9bedcb7735e7))
* **ui:** tri-state (yes/no/unset) selects so editing never silently deletes an explicit 'no' line ([4f8ecf3](https://github.com/ysya/sshelter/commit/4f8ecf387781a5770c3facaa79d7eb84daa1e85d))
* **window:** grant core:window start-dragging + toggle-maximize so the toolbar drags the window ([8a19dc0](https://github.com/ysya/sshelter/commit/8a19dc06651fa778de5662c5fa1c3ea71ed46d44))


### Miscellaneous Chores

* release 0.1.0 ([bc44ffa](https://github.com/ysya/sshelter/commit/bc44ffa6817fd9627d7fe3fc0d077b230a3fc2a2))
* release 0.2.0 ([237c744](https://github.com/ysya/sshelter/commit/237c744b72a0412bd007d1e4528400bfe363cae4))
