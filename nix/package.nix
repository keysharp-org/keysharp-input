{ lib
, stdenv
, cmake
, ninja
, pkg-config
, libevdev
, systemd
, polkit
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "keysharp-input";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [ cmake ninja pkg-config ];
  buildInputs = [ libevdev systemd ];

  cmakeFlags = [
    "-DKEYSHARP_INPUTD_PKCHECK_PATH=${polkit}/bin/pkcheck"
    "-DKEYSHARP_INPUTD_POLKIT_ACTION_DIR=share/polkit-1/actions"
    "-DKEYSHARP_INPUTD_SETUP_ON_INSTALL=OFF"
    "-DKEYSHARP_INPUTD_BUILD_HOOKTEST=OFF"
  ];

  doCheck = true;
  checkPhase = "ctest --output-on-failure";

  meta = {
    description = "Privileged Linux keyboard and mouse hook/synthesis broker";
    homepage = "https://github.com/keysharp-org/keysharp-input";
    license = lib.licenses.mit;
    mainProgram = "keysharp-inputd";
    platforms = lib.platforms.linux;
  };
})
