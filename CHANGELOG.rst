=========
Changelog
=========

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
