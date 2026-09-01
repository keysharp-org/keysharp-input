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
