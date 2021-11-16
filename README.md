# mhynot2
![](https://i.imgur.com/elNjsSM.png)

Cheating is bad, but I think requiring a kernel driver to play a (mostly) single-player game is worse.

mhynot2 is a hook DLL which hooks into various API functions to emulate the functionality of mhyprot2.sys without actually running a driver. Tested on Genshin Impact 2.2.

Even though this is a tool to get around cheat prevention measures, this is intended as a tool for research and experimental purposes and isn't specifically designed for cheating.

**This tool has many flaws and will be detected. You will get banned for using this.**

## Usage
1. Launch the game x64dbg with ScyllaHide on VMProtect
2. Run to the entrypoint.
3. Inject the DLL with Cheat Engine
4. Go!