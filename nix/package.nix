{ lib
, rustPlatform
, src
}:

rustPlatform.buildRustPackage {
  pname = "jackbox_megapicker_patcher";
  version = "0.1.0";

  inherit src;

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "lightningscanner-1.0.2" = "sha256-lWhoFJu6GXd9ti546dH4/igGYN0ioOQKkb9UTp6jun0=";
    };
  };

  buildNoDefaultFeatures = true;

  meta = {
    description = "Patches the Jackbox Megapicker to launch games from custom directories, with an ASAR integrity check bypass";
    mainProgram = "jackbox_megapicker_patcher";
    platforms = lib.platforms.linux;
  };
}
