# ClipboardHistoryThief
As a red teamer, it is common practice to retrieve clipboard data for sensitive information, such as passwords. However, traditionally, only the most recent clipboard data can be extracted.

Windows 10/11, starting with version `1809`, introduced a feature called clipboard history that allows users to access the 25 most recent items that have been copied or cut by pressing `Windows logo key + V`. The service responsible for managing this feature, called `cbdhsvc`, operates via a dedicated process-svchost.exe.

This tool `ClipboardHistoryThief` is specifically designed to extract clipboard history, surpassing the constraint of retrieving only the 25 most recent items. It achieves this by examining the process memory and utilizing pattern search to identify clipboard history data stored in the heap, allowing for the extraction of all available clipboard history data from the process.

Although enabling clipboard history may not be a common practice in client environments, this tool provides the option to enable or disable the clipboard history feature through registry edits without requiring a service restart. Once enabled, simply wait for user clipboard activities and then run the tool again to extract all available clipboard history from the process memory.

## Usage
```
Usage: ClipboardHistoryThief.exe [command]

Command         Description
--------        -----------
dump [file]     Dumps the content of the clipboard history to console/file.
enable          Enables the clipboard history feature.
disable         Disables the clipboard history feature.
check           Checks if clipboard history feature is enabled.
help            Shows this help menu.
```

## Example
Dump all clipboard history
```
ClipboardHistoryThief.exe dump
```

Enable clipboard history feature
```
ClipboardHistoryThief.exe enable
```

## Screenshot
![HowTo](https://github.com/netero1010/ClipboardHistoryThief/raw/main/demo.png)

## Compile
`make`