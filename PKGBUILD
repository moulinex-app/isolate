# Maintainer: Simon Scatton <simon.scatton@outlook.fr>

pkgname=isolate-lib
pkgver=1.8.2
pkgrel=1
pkgdesc="Dynamic library based on the isolate program for the IOI"
arch=('i686' 'x86_64')
url="https://github.com/moulinex-app/isolate"
license=('GPL2')
depends=()
makedepends=('git' 'gcc' 'asciidoc')
provides=('isolate-lib')
conflicts=('isolate' 'isolate-git')
install=$pkgname.install
source=("https://github.com/moulinex-app/isolate/releases/download/v$pkgver/isolate-lib-v$pkgver.tar.gz")

build() {
  cd $pkgname-v$pkgver
  ./configure --prefix="/usr" --sysconfdir="/etc"
}

package() {
  cd $pkgname-v$pkgver
  make DESTDIR="$pkgdir/usr" topsrc_dir="$pkgdir" sysconfdir="$pkgdir/etc" install
  chmod o-x $pkgdir/usr/bin/isolate
}
