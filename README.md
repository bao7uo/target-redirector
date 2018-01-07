# TargetLockOn
TargetLockOn is a Burp Suite Extension which allows you to "Lock-On" to a particular target, by replacing an incorrect target hostname/IP with the intended one.

## Overview

![TargetLockOn screenshot](https://github.com/bao7uo/TargetLockOn/raw/master/images/title_screenshot.png)

This plugin can be very useful in various situations, including where you want to ensure that a particular IP target is specified, where the DNS may resolve to various IP addresses, and you do not want to "fix" DNS using hosts file or similar.

Also, if a staging/test environment is being tested which is full of references to the production environment, then you can add both environments to scope, and allow the scanner to scan all the referenced pages, but whilst ensuring that only the correct targets are scanned.

## Build

This project requires kotlin to build. On Linux, use the following command.

`kotlinc src/burp/*.kt src/TargetLockOn.kt -include-runtime -d TargetLockOn.jar`

## TargetLockOn Roadmap

This project is still under development.

#### Potential future improvements:
- Improve UI
- Exception handling

#### Potential future features:
- Regex matching for search term
- Support for replacing with a different port

## Contribute
Contributions, feedback and ideas will be appreciated.

## License notice

Copyright (C) 2017 Paul Taylor

See LICENSE file for details.
