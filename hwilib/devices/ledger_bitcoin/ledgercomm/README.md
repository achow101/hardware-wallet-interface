# LedgerCOMM

Modified version of the [ledgercomm library](https://github.com/LedgerHQ/ledgercomm).

# Changes

The changes are only to make it work on Python 3.6 as the official library requires 3.8+

* Remove usage of `typing.Literal`
* Change to using relative imports instead of `ledgercomm`
* Add `hid_path` to `Transport` so that the HID path can be given instead of automatically choosing the first device
