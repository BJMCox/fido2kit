# Security policy

fido2kit holds the FIDO2 and vault code that fido2kpxc and fido2lock use to protect passwords, so security reports get priority.

## Report a vulnerability

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. You can also email Jessica Cox at jmcox@posteo.de.

Do not open a public issue for a vulnerability. Expect a first reply within a week.

## Supported versions

Only the latest tag receives fixes. A fix reaches users through new releases of the apps that pin it.

## How the apps use it

The apps depend on the kit by a full commit SHA, not by a tag, so a moved tag cannot change what they build. See CONTRIBUTING.md.
