{ lib
, stdenv
, cmake
, ninja
, pkg-config
, libevdev
, systemd
, polkit
, keysharpPermissionsSource
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "keysharp-input";
  version = "0.2.0";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs = [ libevdev systemd ];

  cmakeFlags = [
    "-DKEYSHARP_PERMISSIONS_SOURCE_DIR=${keysharpPermissionsSource}"
    "-DKEYSHARP_INPUT_PKCHECK_PATH=${polkit}/bin/pkcheck"
    "-DKEYSHARP_INPUT_POLKIT_ACTION_DIR=share/polkit-1/actions"
    "-DKEYSHARP_INPUT_SETUP_ON_INSTALL=OFF"
    # The cmake hook points each install directory at an absolute $out path, which makes
    # CMake bake that prefix into the exported targets instead of deriving it from where
    # the package config is found. The layout is unchanged, but the export stays
    # relocatable, which is what a consumer reading a staged install tree needs.
    "-DCMAKE_INSTALL_BINDIR=bin"
    "-DCMAKE_INSTALL_LIBDIR=lib"
    "-DCMAKE_INSTALL_INCLUDEDIR=include"
    "-DCMAKE_INSTALL_LIBEXECDIR=libexec"
  ];

  doCheck = true;
  checkPhase = "ctest --output-on-failure";

  meta = {
    description = "Privileged Linux keyboard and mouse hook/synthesis broker";
    homepage = "https://github.com/keysharp-org/keysharp-input";
    license = lib.licenses.mit;
    mainProgram = "keysharp-input";
    platforms = lib.platforms.linux;
  };
})
