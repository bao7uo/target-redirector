# TargetLockOn
TargetLockOn is a Burp Suite Extension which allows you to "Lock-On" to a particular target, by replacing an incorrect target hostname/IP with the intended one.

## Overview

![TargetLockOn screenshot](https://github.com/bao7uo/TargetLockOn/raw/master/images/title_screenshot.png)

This plugin can be very useful in various situations where you want to force a particular target IP or hostname to be used. For example:

- testing a staging/pre-production environment which is full of references to the production environment. you can add both environments to scope, and allow the scanner to scan all the referenced pages, but whilst ensuring that only the staging/pre-production targets are scanned
- web application is protected by third-party ddos protection/load balancers which serve the public URL. The third-party servers are not in scope so cannot be tested. A backend target IP/hostname has been provided, but the public URL is referenced all over the target web application
- hostname resolving to multiple IP addresses, but you can only test one IP, and you do not want to the "fix" DNS using hosts file or similar

## Build

This project is written entirely in Kotlin, including the Burp API, and requires Kotlin compiler to build. On Linux, use the following command.

`kotlinc src/burp/*.kt src/TargetLockOn.kt -include-runtime -d TargetLockOn.jar`

See the following page from my other repo which has further details about the Burp API and Kotlin.

- https://github.com/bao7uo/burp-extender-api-kotlin/blob/master/README.md

## Usage

This extension is simple and intuitive. It will search ALL requests made by Burp or proxied by Burp for the hostname/IP specified in the left-hand textbox. If this hostname/IP is found, the extension will replace it with the hostname/IP specified in the right-hand textbox. Status updates are logged in the extension's stdout on Burp's Extender tab.

## TargetLockOn Roadmap

This project is still under development.

#### Potential future improvements:
- Improve UI
- Exception handling

#### Potential future features:
- Regex matching for search term
- Replacing port as well as hostname
- Create session handling actions so that multiple search terms can be used with multiple session handling rules
- Remember/clear history

## Contribute
Contributions, feedback and ideas will be appreciated.

## License notice

Copyright (C) 2017 Paul Taylor

See LICENSE file for details.
