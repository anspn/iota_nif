defmodule IotaNif.MixProject do
  use Mix.Project

  @version "0.3.1"

  def project do
    [
      app: :iota_nif,
      version: @version,
      language: :erlang,
      erlc_paths: ["src", "src/identity", "src/notarization", "src/credential"],
      deps: deps(),
      description: "IOTA NIF library for Erlang/OTP — DID, Verifiable Credentials, and Notarization",
      package: package(),
      source_url: "https://github.com/anspn/iota_nif"
    ]
  end

  def application do
    [
      extra_applications: [:kernel, :stdlib]
    ]
  end

  defp deps do
    []
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/anspn/iota_nif"},
      files: ~w(src include priv mix.exs rebar.config README.md LICENSE)
    ]
  end
end
