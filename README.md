# isolate-lib

This fork of **isolate** is a dynamic library based on the work of Martin Mareš (<mj@ucw.cz>) and Bernard Blackham
(<bernard@blackham.com.au>) on [isolate](https://github.com/ioi/isolate), it exposes API bindings for the Rust crate
that is made for Moulinex. See the original repository for the CLI.


# Install

To compile and install **isolate-lib** you will need the following dependencies :

+ gcc (or any other C compiler supporting C99 and GNU Extensions)
+ GNU Libtool
+ cap

Get the latest release tarball [here](https://github.com/Moulinex/isolate/releases/latest) and install using the following command :

```
./configure && make install
```

The default install directory is ``/usr/local/`` but can be overriden using ``--prefix=dir`` with the ``configure`` script.

For **Arch Linux** users the default install directory should be ``/usr/`` for instance.

# Developers build

If you want to build the project as a developer you will need **GNU Autotools**.

Clone the ``dev`` branch of the git and run the ``./bootstrap`` script to configure the project for development.
