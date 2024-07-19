=========
Changelog
=========

2.3.0
=====

*July 19, 2024*

Small feature release

* The ``Certificate`` model now publicly exposes the ``certificate`` attribute, which
  returns the certificate loaded through ``cryptography``.

2.2.0
=====

*July 18, 2024*

Feature release: encrypted private keys

Note: 2.1.0 was accidentally published to PyPI and has been yanked.

* Added support for uploading of encrypted private keys. These keys require a passphrase
  to be provided and are stored in unencrypted form.
* Added a pytest plugin to expose certificate/key generation fixtures for downstream
  packages.

2.0.0
=====

*March 15, 2024*

**Breaking changes**

* Dropped support for Python versions older than 3.10
* Dropped support for Django 4.1
* Removed certificate chain validity checking as it produced mixed results

**Other changes**

* Confirmed support for Python 3.11 and 3.11
* Confirmed support for Django 4.2
* Replaced PyOpenSSL dependency/usage with cryptography package
* Added mypy type checking to CI pipeline, improved type hints
* Switched package management to ``pyproject.toml`` file

1.4.1
=====

*October 10, 2023*

* Update Manifest to include certificates

1.4.0
=====

*October 10, 2023*

* Add factory to ``test`` module

1.3.0
=====

*February 16, 2023*

* Fixed bug in 1.2.0 due to field validator not being deconstructible
* Format with latest black version
* Confirmed support for Django 4.1
* Dropped django-choices dependency

1.2.0
=====

*January 10, 2023*

* The admin now prevents downloading the private keys
* The admin is now more robust on corrupt certificates/keys, allowing users to correct
  the bad data/files.
* Started refactoring the unittest-based tests into pytest style

1.1.2
=====

*November 15, 2022*

* Fix AttributeError on adding a new certificate

1.1.1
=====

*November 3, 2022*

* Fixed typo in dependencies
* Pinned minimum required versions for the 1.1.0 features to reliably work

1.1.0
=====

*October 14, 2022*

* Updated documentation
* [#3] Added serialnumber of certificates
* [#4] Added chain check of certificates

1.0.0
=====

*August 29, 2022*

* Initial release
