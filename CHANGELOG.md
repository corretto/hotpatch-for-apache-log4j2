# Change Log for Amazon Corretto hotpatch-for-apache-log4j2

The following sections describe the changes for each release of the hotpatch tool.

## Version 1.4.0

Release Date: TBD

### [#39](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/39) Support for multiple patches
The tool now supports applying multiple patches to the same VM in a single attach. Existing patch has been renamed to `Log4j2_JndiNoLookup` and it is applied by default.

### Ongoing Changes ###
See [all changes](https://github.com/corretto/hotpatch-for-apache-log4j2/compare/1.3.0...main) since the previous version.

## Version 1.3.0

Release Date: Dec 16, 2021

The following new features are included in 1.3.0:

### [#30](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/30) Support for JDK7 ###
Changed the compilation target to support attaching to JDK7 virtual machines. Included support for JDK7 on the tests.

### [#28](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/28) Avoids reinstalling the agent after retransformation of loaded classes ###
Improved how the transformer is installed to guarantee there is no time when the transformer is not installed and a copy of the JndiLookup class could be loaded before the new transformer is installed.

### [#32](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/32) Import ASM directly from source ###
Replaced the usage of gradle shadow jar plugin and import a copy of ASM 9.2 directly from source into the target namespace. This allows to build the jar without the need of a dependency manager system. Related to this change is [#27](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/27) to avoid using reflection to resolve the ASM API version, as we are using 9.2.

### [#9](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/9) Add Maven project support ###
Allow building the jar using Maven. This is useful for distributions that do not have access to gradle. [#35](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/35) moves part of the jar information into a common file to be shared by both build systems.

### [#16](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/16) Setup automated integration tests ###
Added GitHub actions support for the Maven [#34](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/34) and Gradle [#36](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/36) build processes. Tests are run against Corretto 8, 11 and 17.

### Other changes ###
See [all changes](https://github.com/corretto/hotpatch-for-apache-log4j2/compare/1.2...1.3.0) since the previous version.

### Acknowledgements ###
Special thanks to [raphw](https://github.com/raphw) and [dagnir](https://github.com/dagnir) for their contributions.

## Version 1.2

**Release Date:** Dec 15, 2021

The following new features are included in 1.2:

### [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11) Gradle build and newer versions ###

This change included multiple improvements

**Allow attaching JDK17**

The tool will now use its own version of ASM to prevent the existing problem when attaching to JDK 17 and trying to use the internal version of ASM.

**Attach when a SecurityManager is installed**

Prevent failures that were causing the tool not to be able to attach to a running JVM if a SecurityManager was installed that prevented the read/write of System Properties.

**Use a single jar for all versions**

Added gradle logic to generate a single jar that should be usable by JDK versions ranging from 8 up to 17.

### [#14](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/14) Added tests ###

Added a suite of tests that can be configured to test the usage of different JDKs to attach the tool.

### Other Changes ###
See [all changes](https://github.com/corretto/hotpatch-for-apache-log4j2/compare/1.0...1.2) since the previous version.

### Acknowledgements ###
Special thanks to [otrosien](https://github.com/otrosien), [mildsunrise](https://github.com/mildsunrise) and [rschmitt](https://github.com/rschmitt) for their contributions.

## Version 1.0

Release Date: Dec 11, 2021

Initial release with support for hotpatching [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046/).

