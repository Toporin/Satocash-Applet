# Satocash-Applet

Open source JavaCard applet for [Cashu](https://cashu.space) ecash.

# Introduction

# Overview

# How to use your Satocash?

# Supported hardware

For supported hardware, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet).

# Build & install

You can build the JavaCard CAP files or use the last [release](https://github.com/Toporin/Seedkeeper-Applet/releases).

## Building using Ant (legacy)

To generate the CAP file from the sources, you can use the [ant-javacard](https://github.com/martinpaljak/ant-javacard) Ant task (see the instructions on the ant-javacard github repository).

For detailed build and installation, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet).

## Building using Gradle (new)

The project can also be built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
Using this approach allows to load the NDEF applet at the same time (allows to automatically open the right application on Android by simply tapping the card).

For compiling the JavaCard code, you first need to download the javacard SDK into the project in the `sdks` folder:

```
git submodule add https://github.com/martinpaljak/oracle_javacard_sdks sdks
```

Then you must set the JavaCard HOME. The gradle.properties file has a setting with the property "com.fidesmo.gradle.javacard.home" set to the correct path.

To compile the JavaCard code and generate a cap file, simply run `./gradlew convertJavacard`. The cap file will be compiled in the `build/javacard/org/satocash/applet` folder.

To load the cap file into a blank smart card, connect a card reader with the card inserted and run `./gradlew install`

## Javacard version compatibility

The JDK versions supported depend on the Javacard SDK used, see more details [in this page](https://github.com/martinpaljak/ant-javacard/wiki/JavaCard-SDK-and-JDK-version-compatibility).

JDK 8 and JDK 11 offer the largest compatibility, but for latest SDKs, JDK 17 also works and is the preferred option.
Currently, we use SDK 3.0.4 with JDK 8 or 11. We plan to switch to SDK 3.2.0 (v25.0) and JDK 17/21 after careful testing.

# SDK (wip)

Several libraries are available to simplify integration of Satocash with client applications:
* Python: Pysatochip (also availabl in [pypi](https://pypi.org/project/pysatochip/))
* Java/Kotlin: [Satochip-Java](https://github.com/Toporin/Satochip-Java)
* Swift:  [SatochipSwift](https://github.com/Toporin/SatochipSwift)

# Tests (wip)

Python unit tests are available through the [pysatochip module](https://github.com/Toporin/pysatochip).

The unit tests can be performed using:
```python -m unittest -v test_satocash```

# License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. [Contact me](mailto:satochip.wallet@gmail.com) if you feel that some license combination is inappropriate.
