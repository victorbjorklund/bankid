defmodule BankID.MixProject do
  use Mix.Project

  @version "0.0.1"
  @source_url "https://github.com/victorbjorklund/bankid"

  def project do
    [
      app: :bankid,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      # HTTP client for BankID API
      {:req, "~> 0.5.0"},

      # QR code generation
      {:qrcode_ex, "~> 0.1.0"},

      # Documentation
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Pure Elixir client for Swedish BankID authentication and signing.
    Provides low-level API access with mTLS support, QR code generation,
    and support for both test and production environments.
    """
  end

  defp package do
    [
      name: "bankid",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url
      },
      files: ~w(lib priv .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      extras: [
        "README.md"
      ],
      groups_for_modules: [
        Core: [
          BankID,
          BankID.Client
        ],
        "QR Code Generation": [
          BankID.QRCode
        ],
        "HTTP Client": [
          BankID.HTTPClient
        ]
      ],
      nest_modules_by_prefix: [
        BankID
      ]
    ]
  end
end
