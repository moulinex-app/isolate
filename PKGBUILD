# Maintainer: Simon Scatton <simon.scatton@outlook.fr>

pkgname=isolate-lib
pkgver=1.8.2
pkgrel=1
pkgdesc="Dynamic library based on the isolate program for the IOI"
arch=('i686' 'x86_64')
url="https://github.com/moulinex-app/isolate"
license=('GPL2')
depends=()
makedepends=('git' 'gcc' 'libcap')
provides=('isolate-lib')
conflicts=('isolate' 'isolate-git')
install=$pkgname.install
source=("file://$pkgname-v$pkgver.tar.gz")
sha512sums=("1d30a7da66aaf2c420cd007a3e78abbb66d6b12742659ce43a014985b20ef6b27149f4d62ef44108852af8a59adedef439ffbc2079a26407e58ab0f62615010f")
build() {
  cd $pkgname-v$pkgver
  ./configure --prefix="/usr"
}

package() {
  cd $pkgname-v$pkgver
  make DESTDIR="$pkgdir" install
}
