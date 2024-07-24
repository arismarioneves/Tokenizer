# Changelog

All notable changes to this project will be documented in this file.

# 2.0 (2024-07-24)
* The validity of the token is now only required at the time of creation, and the key derivation and encoding/decoding methods have been improved.

# 1.7 (2024-07-23)
* Added a default time zone to the date (Y-m-d) and the validity of the token (1 day) has by default false.

# 1.6 (2024-07-23)
* Fixed path in the `composer.json` file to point to the correct directory.

# 1.5 (2024-07-23)
* Publish the library on Packagist

# 1.1 (2024-07-22)
* Implemented a derived key and an initialization vector so that each encrypted message is unique, even if the same original text and key are used.

# 1.0 (2024-07-21)
* Initial release
