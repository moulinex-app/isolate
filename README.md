# isolate-lib

This fork of **isolate** is a dynamic library based on the work of Martin Mareš (<mj@ucw.cz>) and Bernard Blackham
(<bernard@blackham.com.au>) on [isolate](https://github.com/ioi/isolate), it exposes API bindings for the Rust crate
that is made for Moulinex. See the original repository for the CLI.


# Install

## Arch Linux users

The isolate library can be installed via the [AUR](https://aur.archlinux.org/packages/isolate-lib/) package ``isolate-lib`` using a AUR builder such as ``yay``

## Install from source

To compile and install **isolate-lib** you will need the following dependencies :

+ gcc (or any other C compiler supporting C99 and GNU Extensions)
+ GNU Libtool
+ cap

Get the latest release tarball [here](https://github.com/moulinex-app/isolate/releases/latest) and install using the following command :

```
./configure
```

Once the configuration is done you can modify the configuration file ``isolate.cf`` of the library. And then proceed to 

```
make install
```

The configuration file will be install at ``$PREFIX/etc/isolate.cf`` where prefix is the install directory of the configure script.

The default install directory is ``/usr/local/`` but can be overriden using ``--prefix=dir`` with the ``configure`` script.

# Developers build

If you want to build the project as a developer you will need **GNU Autotools**.

Clone the ``dev`` branch of the git and run the ``./bootstrap`` script to configure the project for development.
