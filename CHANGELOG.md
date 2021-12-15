# Change Log for Amazon Corretto hotpatch-for-apache-log4j2

The following sections describe the changes for each release of the hotpatch tool.

## Version: 1.2

Release Date: Dec 15, 2021


The following new features are included in 1.2:

**Allow attaching JDK17**

The tool will now use its own version of ASM to prevent the existing problem when attaching to JDK 17 and trying to use the internal version of ASM.

**Attach when a SecurityManager is installed**

Prevent failures that were causing the tool not to be able to attach to a running JVM if a SecurityManager was installed that prevented the read/write of System Properties.

**Use a single jar for all versions**

Added gradle logic to generate a single jar that should be usable by JDK versions ranging from 8 up to 17.

**Added tests**

Added a suite of tests that can be configured to test the usage of different JDKs to attach the tool.

### Detailed list of changes
|  Link  | Description |
| --- | --- |
| [#7](https://github.com/corretto/hotpatch-for-apache-log4j2/issues/7) | Remove UTF-8 chars from files that were causing compilation errors in [#6](https://github.com/corretto/hotpatch-for-apache-log4j2/issues/6) |
| [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11) | Use gradle to implement build logic
| [40ef9687](https://github.com/corretto/hotpatch-for-apache-log4j2/commit/40ef9687a2b366af7ca96b5df7ca4ae99031b001) | Pushed with [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11), replaces the use of the target VM ASM with a shadow version of ASM 9.2 to allow attaching to 17 |
| [5dfce447](https://github.com/corretto/hotpatch-for-apache-log4j2/commit/5dfce4471ad4e0ffd73bfedfaf2cea122237739a) | Pushed with [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11), no longer generate a jar for the agent on the fly, but use the one built with gradle |
| [34e1a0c4](https://github.com/corretto/hotpatch-for-apache-log4j2/commit/34e1a0c45859963f61543d2f05e4e2f68d7fd7ba) | Pushed with [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11), fixes issues in the jar packaging class names |
| [2bde240c](https://github.com/corretto/hotpatch-for-apache-log4j2/commit/2bde240c47a510816fbe25d607858c93c1889f16) | Pushed with [#11](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/11), fixes issues attaching when a SecurityManager is installed |
| [#14](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/14) | Add shell based tests |
| [#19](https://github.com/corretto/hotpatch-for-apache-log4j2/pull/19) | Fixes missing `gradle/wrapper/gradle-wrapper.jar`

Special thanks to [otrosien](https://github.com/otrosien), [mildsunrise](https://github.com/mildsunrise) and [rschmitt](https://github.com/rschmitt) for their contributions.

## Version: 1.0

Release Date: Dec 11, 2021

Initial release with support for hotpatching [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046/).

