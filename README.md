# Target Redirector
[![Language](https://img.shields.io/badge/Lang-Kotlin-blue.svg)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

Target Redirector is a Burp Suite Extension which allows you to redirect requests to a particular target by replacing an incorrect target hostname/IP with the intended one. The request HTTP headers and body are unaffected, only the actual connection target itself is replaced.

## Overview

![Target Redirector screenshot](images/title_screenshot.png)

This plugin is useful in various situations where you want to force a particular target IP or hostname to be used. For example:

- testing a staging/pre-production environment which is full of references to the production environment. you can add both environments to scope, and allow the scanner to scan all the referenced pages, but whilst ensuring that only the staging/pre-production targets are scanned
- web application is protected by third-party ddos protection/load balancers which serve the public URL. The third-party servers are not in scope so cannot be tested. A backend target IP/hostname has been provided, but the public URL is referenced all over the target web application
- hostname resolving to multiple IP addresses, but you can only test one IP, and you do not want to the "fix" DNS using hosts file or similar

## Build / Requirements

This project is written in Kotlin, although is currently built with the regular Java Burp API. Building from source requires the Kotlin compiler (tested with kotlinc-jvm 1.2.10).

To build, use the following command which has been tested successfully on both Windows and Linux.

- `kotlinc -classpath burp-extender-api-1.7.22.jar src/main/kotlin/target-redirector.kt -include-runtime -d target-redirector.jar`

The project can be built against a Kotlin version of the Burp API. See the following page from my other repo which has further details about the Burp API and Kotlin.

- https://github.com/bao7uo/burp-extender-api-kotlin/blob/master/README.md

To build with the Kotlin Burp API, place the API kt source files in the `src/main/kotlin/burp directory` and build with the following command.

- `kotlinc src/main/kotlin/burp/*.kt src/main/kotlin/target-redirector.kt -include-runtime -d target-redirector.jar`

## Usage

This extension is simple and intuitive. It will search ALL requests made by Burp or proxied by Burp for the hostname/IP specified in the left-hand textbox. If this hostname/IP is found, the extension will replace it with the hostname/IP specified in the right-hand textbox. Status updates are logged in the extension's stdout on Burp's Extender tab.

## Target Redirector Roadmap

This project is still under development.

#### Potential future improvements:
- Improve UI
- Exception handling

#### Potential future features:
- Replacing port as well as hostname
- Regex matching for search term
- Multiple search terms/redirections
- Session handling actions
- History, monitoring, loggins

## Contribute
Contributions, feedback and ideas will be appreciated.

## License notice

Copyright (C) 2016-2018 Paul Taylor

See LICENSE file for details.
