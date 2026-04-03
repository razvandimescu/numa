# Maintainer: razvandimescu <razvan@dimescu.com>
pkgname=numa-git
_pkgname=numa
pkgver=0.9.1.r0.g1234abc # Updated by pkgver()
pkgrel=1
pkgdesc="Portable DNS resolver in Rust — .numa local domains, ad blocking, developer overrides, DNS-over-HTTPS"
arch=('x86_64' 'aarch64')
url="https://github.com/razvandimescu/numa"
license=('MIT')
depends=('gcc-libs' 'glibc')
makedepends=('cargo' 'git')
provides=("$_pkgname")
conflicts=("$_pkgname")
source=("$_pkgname::git+$url.git")
sha256sums=('SKIP')

pkgver() {
  cd "$srcdir/$_pkgname"
  ( set -o pipefail
    git describe --long --tags 2>/dev/null | sed 's/\([^-]*-g\)/r\1/;s/-/./g' ||
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
  ) | sed 's/^v//'
}

prepare() {
  cd "$srcdir/$_pkgname"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked
}

build() {
  cd "$srcdir/$_pkgname"
  export RUSTUP_TOOLCHAIN=stable
  cargo build --frozen --release
}

check() {
  cd "$srcdir/$_pkgname"
  export RUSTUP_TOOLCHAIN=stable
  cargo test --frozen
}

package() {
  cd "$srcdir/$_pkgname"
  install -Dm755 "target/release/$_pkgname" "$pkgdir/usr/bin/$_pkgname"
  
  # Install service file with patched path
  sed 's|ExecStart=/usr/local/bin/numa|ExecStart=/usr/bin/numa /etc/numa.toml|g' numa.service > numa.service.patched
  install -Dm644 "numa.service.patched" "$pkgdir/usr/lib/systemd/system/numa.service"
  
  install -Dm644 "numa.toml" "$pkgdir/etc/numa.toml"
  install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
