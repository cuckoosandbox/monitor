monitor
=======

The new Cuckoo Monitor. [Click here for documentation][docs].
If at first it doesn't compile, just try a second time!

Note that you'll need the `pyyaml` package, which may be installed as follows:
`pip install pyyaml`.

And the `docutils` package:
`pip install docutils`.

[docs]: http://cuckoo-monitor.readthedocs.org/en/latest/

## Step by step of compiling the C files inside tests/
1. `make` in the root directory
2. `cd test/`
3. `./unittest.py` run the unittests one time in the test/ directory
4. `make` in the test/ folder

The compiled executeables are now inside the test/x64/ and test/x86/ folder.

