# mhynot2
![](https://i.imgur.com/elNjsSM.png)

Cheating is bad, but I think requiring a kernel driver to play a (mostly) single-player game is worse.

mhynot2 is a hook DLL which hooks into various API functions to emulate the functionality of mhyprot2.sys without actually running a driver. Tested on Genshin Impact 2.2, 2.3, 2.4, 2.5 (mhyprot3.sys not used WTF?????????), 2.6 (mhyprot3.sys used for some people?), and 2.7 (THEY WENT BACK TO MHYPROT2!!!!!).

Even though this is a tool to get around cheat prevention measures, this is intended as a tool for research and experimental purposes and isn't specifically designed for cheating.

**This tool has many flaws and will be detected. You will get banned for using this.**

## Usage
Compile and run https://gist.github.com/khang06/56e3c221769648132023daab9fd2bc39

or...

1. Launch the game with x64dbg with ScyllaHide on the VMProtect preset
2. Run to the game's entrypoint
3. Inject the DLL with Cheat Engine
4. Go!

## Linux build
1. Init/update git submodules
1. Go to `minhook` directory and build it with `CROSS_PREFIX=x86_64-w64-mingw32- make -f build/MinGW/Makefile`
1. Run `mkdir build && cd build && cmake .. && make -j256`
1. Grab `mhynot2.dll` and inject it together with `libwinpthread-1.dll`
