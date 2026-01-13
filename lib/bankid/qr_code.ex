defmodule BankID.QRCode do
  @moduledoc """
  QR code generation for BankID authentication.

  This module provides helpers for generating animated QR codes that refresh
  according to BankID's time-based HMAC algorithm.

  ## Usage

      # Generate QR code content
      qr_content = BankID.QRCode.generate_content(
        qr_start_token,
        start_time,
        qr_start_secret
      )

      # Generate QR code SVG
      svg = BankID.QRCode.generate_svg(
        qr_start_token,
        start_time,
        qr_start_secret,
        width: 256
      )

  The QR code must be regenerated every second with the current time
  to maintain the time-based HMAC that BankID requires.
  """

  # Type definitions

  @typedoc """
  Options for QR code generation.

  ## Options
  - `:width` - Width of the QR code in pixels (default: 256)
  - `:shape` - Shape of QR modules ("square" or "circle", default: "square")
  - `:color` - Color of the QR code modules (default: "#000")
  - `:background_color` - Background color of the QR code (default: "#FFF")
  """
  @type qr_options :: keyword()

  @doc """
  Generate the time-based HMAC content for a BankID QR code.

  This uses BankID's algorithm: bankid.<qr_start_token>.<elapsed_time>.<hmac>

  This is a native Elixir implementation that matches the behavior of the Python
  pybankid library's `generate_qr_code_content` function.

  ## Parameters
  - qr_start_token: Token from authentication response
  - start_time: Timestamp when authentication was initiated (Unix timestamp in seconds)
  - qr_start_secret: Secret from authentication response

  ## Returns
  String containing the QR code content in BankID format

  ## Algorithm
  Based on pybankid library (https://github.com/hbldh/pybankid/blob/master/bankid/qr.py):
  1. Calculate elapsed seconds: floor(current_time - start_time)
  2. Generate HMAC-SHA256: hmac(secret, elapsed_seconds_as_string)
  3. Format: "bankid.<token>.<elapsed>.<hmac_hex>"
  """
  @spec generate_content(String.t(), integer(), String.t()) :: String.t()
  def generate_content(qr_start_token, start_time, qr_start_secret) do
    require Logger

    # Calculate elapsed seconds since authentication started
    # Using floor (via trunc for positive numbers) like Python implementation
    current_time = System.system_time(:second)
    elapsed_seconds_since_call = trunc(current_time - start_time)

    Logger.debug("BankID.QRCode.generate_content: elapsed=#{elapsed_seconds_since_call}")

    # Convert elapsed seconds to string for HMAC
    elapsed_seconds_str = Integer.to_string(elapsed_seconds_since_call)

    # Generate HMAC-SHA256 using the secret and elapsed time
    # Python: hmac.new(secret.encode(), msg=str(elapsed).encode(), digestmod=hashlib.sha256).hexdigest()
    # Elixir: :crypto.mac(:hmac, :sha256, secret, message) |> Base.encode16(case: :lower)
    qr_auth_code =
      :crypto.mac(:hmac, :sha256, qr_start_secret, elapsed_seconds_str)
      |> Base.encode16(case: :lower)

    # Format: bankid.<token>.<elapsed>.<hmac>
    content = "bankid.#{qr_start_token}.#{elapsed_seconds_since_call}.#{qr_auth_code}"

    Logger.debug("QR content generated: #{content}")
    content
  end

  @doc """
  Generate a QR code SVG from BankID authentication data.

  ## Parameters
  - qr_start_token: Token from authentication response
  - start_time: Timestamp when authentication was initiated (Unix timestamp)
  - qr_start_secret: Secret from authentication response
  - opts: Optional keyword list for QR code generation:
    - :width - Width of the QR code (default: 256)
    - :shape - Shape of the QR code ("square" or "circle", default: "square")
    - :color - Color of the QR code (default: "#000")
    - :background_color - Background color (default: "#FFF")

  ## Returns
  SVG string ready to be embedded in HTML

  ## Examples

      # Basic QR code
      svg = BankID.QRCode.generate_svg(token, start_time, secret)

      # Customized QR code
      svg = BankID.QRCode.generate_svg(token, start_time, secret,
        width: 300,
        color: "#0066CC",
        shape: "circle"
      )
  """
  @spec generate_svg(String.t(), integer(), String.t(), qr_options()) :: String.t()
  def generate_svg(qr_start_token, start_time, qr_start_secret, opts \\ []) do
    require Logger
    width = Keyword.get(opts, :width, 256)
    shape = Keyword.get(opts, :shape, "square")
    color = Keyword.get(opts, :color, "#000")
    background_color = Keyword.get(opts, :background_color, "#FFF")

    # Generate the QR code content (elapsed_seconds calculated internally)
    qr_content = generate_content(qr_start_token, start_time, qr_start_secret)

    Logger.debug("About to encode QR content: #{qr_content}")

    # Encode to SVG
    svg =
      qr_content
      |> QRCodeEx.encode()
      |> QRCodeEx.svg(
        width: width,
        shape: shape,
        color: color,
        background_color: background_color
      )

    Logger.debug(
      "Generated SVG length: #{String.length(svg)}, first 100 chars: #{String.slice(svg, 0, 100)}"
    )

    svg
  end

  @doc """
  Calculate elapsed seconds since authentication start.

  ## Parameters
  - start_time: Unix timestamp when authentication was initiated

  ## Returns
  Integer number of seconds elapsed
  """
  @spec elapsed_seconds(integer()) :: integer()
  def elapsed_seconds(start_time) do
    trunc(System.system_time(:second) - start_time)
  end
end
