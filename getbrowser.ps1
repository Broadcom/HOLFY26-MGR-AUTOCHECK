$regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice"
Get-ItemPropertyValue -Path $regPath -Name "ProgId"