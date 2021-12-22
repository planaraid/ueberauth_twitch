defmodule UeberauthTwitch.Mixfile do
  use Mix.Project

  @version "0.2.0"
  @url "https://github.com/planaraid/ueberauth_twitch"

  def project do
    [
      app: :ueberauth_twitch,
      version: @version,
      elixir: "~> 1.3",
      name: "Ueberauth Twitch",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      source_url: @url,
      homepage_url: @url,
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [applications: [:logger, :oauth2, :ueberauth]]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.6.3"},
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ex_doc, "~> 0.19", only: :dev},
      {:earmark, ">= 0.0.0", only: :dev}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Uberauth strategy for Twitch authentication."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Dion Ridley"],
      licenses: ["MIT"],
      links: %{GitHub: @url}
    ]
  end
end
