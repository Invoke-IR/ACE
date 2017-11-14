Get-ChildItem "$($PSScriptRoot)\Cmdlets\*" -Include '*.ps1' |
    ForEach-Object {. $_.FullName}