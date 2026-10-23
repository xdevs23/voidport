{ lib, python3Minimal, writeShellScriptBin, symlinkJoin }:
let
  # The verdict program loads the event client from its own directory.
  scripts = lib.fileset.toSource {
    root = ../tests;
    fileset = lib.fileset.unions [
      ../tests/guest-events.py
      ../tests/mount-verdicts.py
    ];
  };
  program = name: script: writeShellScriptBin name ''
    exec ${python3Minimal}/bin/python3 ${scripts}/${script} "$@"
  '';
in
symlinkJoin {
  name = "voidport-guest-events";
  paths = [
    (program "guest-event" "guest-events.py")
    (program "guest-verdict" "mount-verdicts.py")
  ];
}
