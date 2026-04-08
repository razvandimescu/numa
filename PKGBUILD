# Maintainer: razvandimescu <razvan@dimescu.com>
pkgname=numa-git
_pkgname=numa
pkgver=0.10.1.r0.g0000000 # Placeholder — pkgver() rewrites this on each makepkg run
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
  # numa v0.10.1+ uses FHS-compliant paths on Linux by default
  # (/var/lib/numa for data, journalctl for logs), so no source
  # patching is needed. The earlier sed targeted /usr/local/bin/numa,
  # which only appears in a comment in current main.
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

  # numa.service uses {{exe_path}} as a placeholder substituted by
  # `numa install` at runtime via replace_exe_path(). For an AUR
  # package install (no `numa install` step), we substitute it
  # statically here so systemd gets a real ExecStart path.
  sed 's|{{exe_path}}|/usr/bin/numa /etc/numa.toml|g' numa.service > numa.service.patched
  install -Dm644 "numa.service.patched" "$pkgdir/usr/lib/systemd/system/numa.service"

  install -Dm644 "numa.toml" "$pkgdir/etc/numa.toml"
  install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
