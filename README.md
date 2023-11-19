# PowerShell Profile

Originally Tim Sneath's profile. Modified by Chris Titus - [link to his repo](https://github.com/ChrisTitusTech/powershell-profile)

## Instructions

Import the profile into the `~\Documents\WindowsPowerShell` directory.

Using an elevated prompt (admin privileges), execute the following command in PowerShell in order to load the profile when PowerShell opens:

```
Set-ExecutionPolicy RemoteSigned
```

With the elevated prompt, install the following packages using chocolatey:

```
choco install $pkg
```

pkgs:

- gh
- oh-my-posh
- poshgit

### Missing Fonts

Will need to download fonts to make everything work properly - more info can be found [at this link](https://christitus.com/pretty-powershell/) from Chris Titus Tech.

### Final Steps

Make sure that terminal is the default Windows terminal app -- **NOT** PowerShell.

Though, PowerShell is the default profile, and (x86) is the suggested app to use when wanting an non-admin terminal window.

## Future features:

- Get the terminal icons working
