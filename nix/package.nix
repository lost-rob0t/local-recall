{
  python314Packages,
}:
python314Packages.buildPythonPackage {
  pname = "local-recall";
  version = "0.1.0.dev0";
  pyproject = true;
  src = ../.;

  build-system = [ python314Packages.hatchling ];
  dependencies = with python314Packages; [
    pydantic
    pykka
    pynacl
    pyzmq
    typer
  ];

  pythonImportsCheck = [ "local_recall" ];
  doCheck = false;

  postInstall = ''
    mkdir -p $out/share/bash-completion/completions
    mkdir -p $out/share/zsh/site-functions
    mkdir -p $out/share/fish/vendor_completions.d
    $out/bin/local-recall --show-completion bash \
      > $out/share/bash-completion/completions/local-recall
    $out/bin/local-recall --show-completion zsh \
      > $out/share/zsh/site-functions/_local-recall
    $out/bin/local-recall --show-completion fish \
      > $out/share/fish/vendor_completions.d/local-recall.fish
  '';

  meta = {
    description = "Local-first encrypted desktop activity recall";
    mainProgram = "local-recall";
  };
}
