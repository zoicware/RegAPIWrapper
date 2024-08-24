## Windows Registry API Wrapper

### About
This PowerShell module allows you to easily interact with the [Registry Functions](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions) apart of the advapi32 dll.

Current Implemented Functions
 - Create-RegKey (RegCreateKeyEx)
 - Delete-RegKey (RegDeleteKeyEx)
 - Set-RegKeyValue (RegSetValueEx & RegOpenKeyEx)

### Usage

Import the module in PowerShell :
```powershell
Import-Module "PATH_TO_MODULE"
```

View the module file for a description and examples of usage for each function


### Script Example
```powershell

Import-Module 'C:\Users\Admin\Desktop\RegAPIWrapper.psm1' *>$null #suppress warning
#create reg key 'HKLM\Software\TEST'
Create-RegKey -Hive HKLM -Subkey 'Software\TEST'
#add a value to the key
Set-RegKeyValue -Hive HKLM -Subkey 'Software\TEST' -ValueName 'TestKey' -ValueType DWord -ValueData 69
#delete the reg key
Delete-RegKey -Hive HKLM -Subkey 'Software\TEST'

```
