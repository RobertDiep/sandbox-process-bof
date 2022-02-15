# Sandbox AVs (or other processes)
This is a BOF implementation using direct syscalls of the excellent technique by [Elastic's Gabriel Landau](https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/). Make sure to `getsystem` first using Cobalt Strike, or elevate your shell to SYSTEM when running standalone first!

## Usage
_Note: only x64 supported currently!_

Load the [CNA script](sandbox-process.cna) in Cobalt Strike, then run `sandbox-process <pid>` in a Beacon that has SYSTEM privileges (easy using `getsystem`).

This will set the token of target process to Untrusted as well as strip all token privileges.

## Building
Make sure mingw-w64 is installed and run `make`. The BOF will be written to the [bin](bin) directory.

Running `make test` will result in an x64 executable you can use for testing or when you're on a target system.

## Credits
* Original idea: https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/
* Direct syscalls: https://github.com/jthuraisamy/SysWhispers2
* Direct syscalls using a BOF: https://github.com/FalconForceTeam/SysWhispers2BOF
* Large parts of the token handling code: https://github.com/EspressoCake/Toggle_Token_Privileges_BOF/

